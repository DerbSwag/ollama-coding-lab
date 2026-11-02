# Static analysis only. No repository code is built or executed.
[CmdletBinding()]
param([string]$RepositoryPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# PowerShell 7 may otherwise turn expected scanner exit code 1 into an exception.
$PSNativeCommandUseErrorActionPreference = $false
if (-not $RepositoryPath) { $RepositoryPath = Split-Path -Parent $PSScriptRoot }
$root = (Resolve-Path -LiteralPath $RepositoryPath).Path
$output = Join-Path $root '.evidence'
New-Item -ItemType Directory -Path $output -Force | Out-Null
$summaryPath = Join-Path $output 'gate.json'
$summary = [ordered]@{
    schemaVersion = 1
    scannedAtUtc = [DateTime]::UtcNow.ToString('o')
    status = 'error'
    policy = 'Hadolint warning or above; Trivy HIGH/CRITICAL vulnerabilities or misconfigurations; tool errors fail closed'
    hadolint = [ordered]@{ status = 'not-run'; exitCode = $null }
    trivy = [ordered]@{ status = 'not-run'; exitCode = $null }
    ollamaUsedForGate = $false
}
# Replace old results first: a failed invocation must never leave an old PASS.
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
foreach ($reportName in @('hadolint.json', 'trivy.json')) {
    Set-Content -LiteralPath (Join-Path $output $reportName) -Value '' -Encoding UTF8
}

function Get-BlockingFindingCount {
    param([string]$Name, [string]$Json)
    # Wrapping preserves empty/singleton arrays on both Windows PowerShell 5.1
    # and PowerShell 7. Parsing an array directly would enumerate its contents.
    $report = (ConvertFrom-Json -InputObject ('{"report":' + $Json + '}') -ErrorAction Stop).report
    $count = 0
    if ($Name -eq 'Hadolint') {
        if ($report -isnot [Array]) { throw 'Expected Hadolint array' }
        foreach ($finding in $report) {
            if ($finding -isnot [PSCustomObject] -or
                $finding.code -isnot [string] -or [string]::IsNullOrWhiteSpace($finding.code) -or
                $finding.level -cnotin @('error', 'warning', 'info', 'style')) {
                throw 'Invalid Hadolint finding'
            }
            if ($finding.level -cin @('error', 'warning')) { $count++ }
        }
    }
    else {
        if ($report -isnot [PSCustomObject] -or
            ($report.SchemaVersion -isnot [int] -and $report.SchemaVersion -isnot [long]) -or
            $report.SchemaVersion -ne 2 -or
            $report.Results -isnot [Array]) { throw 'Invalid Trivy report' }
        foreach ($result in $report.Results) {
            if ($result -isnot [PSCustomObject]) { throw 'Invalid Trivy result' }
            foreach ($category in @('Vulnerabilities', 'Misconfigurations')) {
                $property = $result.PSObject.Properties[$category]
                if ($null -eq $property) { continue }
                if ($property.Value -isnot [Array]) { throw 'Expected Trivy finding array' }
                foreach ($finding in $property.Value) {
                    if ($finding -isnot [PSCustomObject] -or
                        $finding.Severity -cnotin @('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) {
                        throw 'Invalid Trivy severity'
                    }
                    if ($category -eq 'Vulnerabilities') {
                        if ($finding.VulnerabilityID -isnot [string] -or
                            [string]::IsNullOrWhiteSpace($finding.VulnerabilityID)) { throw 'Invalid vulnerability ID' }
                        if ($finding.Severity -cin @('HIGH', 'CRITICAL')) { $count++ }
                    }
                    else {
                        if ($finding.ID -isnot [string] -or [string]::IsNullOrWhiteSpace($finding.ID) -or
                            $finding.Status -cnotin @('FAIL', 'PASS', 'EXCEPTION')) { throw 'Invalid misconfiguration' }
                        if ($finding.Status -ceq 'FAIL' -and $finding.Severity -cin @('HIGH', 'CRITICAL')) { $count++ }
                    }
                }
            }
        }
    }
    return $count
}

function Invoke-Scanner {
    param([string]$Name, [string[]]$Arguments, [string]$ReportName)
    $code = $null
    $blockingFindings = $null
    try {
        $lines = @(& docker @Arguments)
        $code = $LASTEXITCODE
        $json = $lines -join "`n"
        # Retain stdout for diagnosis even when validation fails; only a validated
        # report consistent with the exit code can authorize PASS.
        $json | Set-Content -LiteralPath (Join-Path $output $ReportName) -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($json)) { throw 'Missing scanner output' }
        $blockingFindings = Get-BlockingFindingCount -Name $Name -Json $json
        $status = 'error'
        $reason = 'unexpected-exit-code'
        if ($code -eq 0 -or $code -eq 1) {
            $reason = 'json-exit-code-mismatch'
            if ($code -eq 0 -and $blockingFindings -eq 0) { $status = 'pass'; $reason = 'consistent' }
            elseif ($code -eq 1 -and $blockingFindings -gt 0) { $status = 'findings'; $reason = 'consistent' }
        }
        return [ordered]@{ status = $status; exitCode = $code; blockingFindings = $blockingFindings; reason = $reason }
    }
    catch {
        Write-Warning "$Name failed to produce a valid report. Gate will fail."
        return [ordered]@{
            status = 'error'; exitCode = $code; blockingFindings = $blockingFindings
            reason = 'execution-or-report-error'
        }
    }
}

try {
    $null = Get-Command docker -ErrorAction Stop
    if (-not (Test-Path -LiteralPath (Join-Path $root 'Dockerfile') -PathType Leaf)) {
        throw 'Root Dockerfile is required for this lab.'
    }
    $images = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'security-tools.json') -Raw | ConvertFrom-Json
    foreach ($image in @($images.hadolint, $images.trivy)) {
        if ($image -notmatch '@sha256:[a-f0-9]{64}$') { throw 'Scanner images must be digest pinned.' }
    }
    $mount = "type=bind,source=$root,target=/workspace,readonly"
    $common = @('run', '--rm', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--mount', $mount)
    $summary.hadolint = Invoke-Scanner -Name 'Hadolint' -ReportName 'hadolint.json' -Arguments ($common + @(
        '--network=none', $images.hadolint, 'hadolint', '--format', 'json',
        '--failure-threshold', 'warning', '/workspace/Dockerfile'
    ))
    # Trivy needs network for vulnerability databases and policy bundles.
    # Only /tmp is writable; no Docker socket, credentials or home directory mount.
    # Explicitly disable repo-supplied config/ignore files and disable telemetry/version checks.
    $summary.trivy = Invoke-Scanner -Name 'Trivy' -ReportName 'trivy.json' -Arguments ($common + @(
        '--tmpfs', '/tmp:rw,nosuid,nodev', $images.trivy,
        '--cache-dir', '/tmp/trivy-cache', '--config', '/dev/null', 'fs',
        '--scanners', 'vuln,misconfig', '--severity', 'HIGH,CRITICAL',
        '--exit-code', '1', '--format', 'json', '--timeout', '10m',
        '--skip-version-check', '--ignorefile', '/dev/null',
        '--skip-dirs', '/workspace/.git', '--skip-dirs', '/workspace/.evidence',
        '--skip-dirs', '/workspace/node_modules',
        '--skip-files', '**/.env', '--skip-files', '**/.env.*',
        '--skip-files', '**/*.pem', '--skip-files', '**/*.key',
        '--skip-files', '**/*.pfx', '--skip-files', '**/*.p12', '/workspace'
    ))
    if ($summary.hadolint.status -eq 'pass' -and $summary.trivy.status -eq 'pass') {
        $summary.status = 'pass'
    }
    elseif ($summary.hadolint.status -eq 'error' -or $summary.trivy.status -eq 'error') {
        $summary.status = 'error'
    }
    else { $summary.status = 'fail' }
}
catch {
    Write-Warning 'Audit prerequisite or runtime error. Gate will fail.'
    $summary.status = 'error'
}
finally {
    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
}
Write-Host "Security gate: $($summary.status). Reports: .evidence/"
if ($summary.status -ne 'pass') { exit 1 }
exit 0
