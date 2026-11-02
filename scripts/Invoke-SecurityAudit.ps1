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

function Invoke-Scanner {
    param([string]$Name, [string[]]$Arguments, [string]$ReportName)
    try {
        $lines = @(& docker @Arguments)
        $code = $LASTEXITCODE
        $json = $lines -join "`n"
        # Require parsable scanner output even when the executable exits zero.
        if ([string]::IsNullOrWhiteSpace($json)) { throw 'Missing scanner output' }
        $parsed = ConvertFrom-Json -InputObject $json -ErrorAction Stop
        if ($Name -eq 'Hadolint') {
            if ($json -notmatch '^\s*\[') { throw 'Expected Hadolint JSON array' }
        }
        elseif ($null -eq $parsed -or $parsed.SchemaVersion -ne 2) {
            throw 'Expected Trivy schema version 2'
        }
        $json | Set-Content -LiteralPath (Join-Path $output $ReportName) -Encoding UTF8
        $status = 'error'
        if ($code -eq 0) { $status = 'pass' }
        elseif ($code -eq 1) { $status = 'findings' }
        return [ordered]@{ status = $status; exitCode = $code }
    }
    catch {
        Write-Warning "$Name failed to produce a valid report. Gate will fail."
        return [ordered]@{ status = 'error'; exitCode = $null }
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
