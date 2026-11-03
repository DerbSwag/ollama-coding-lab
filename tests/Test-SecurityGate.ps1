# Mock only Docker; exercise the real script, verdict, exit code and evidence files.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$fixture = Join-Path $root ('.evidence/gate-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture -Force | Out-Null
Set-Content -LiteralPath (Join-Path $fixture 'Dockerfile') -Value 'FROM scratch' -Encoding UTF8
$cleanTrivy = '{"SchemaVersion":2,"Results":[]}'
$warning = '[{"code":"DL3000","level":"warning","message":"synthetic"}]'
$highVuln = '{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"SYNTHETIC-001","Severity":"HIGH"}]}]}'
$highMisconf = '{"SchemaVersion":2,"Results":[{"Misconfigurations":[{"ID":"SYNTHETIC-002","Severity":"HIGH","Status":"FAIL"}]}]}'

function New-Case {
    param([string]$Name, [string]$Scanner = 'hadolint', [string]$Json = '[]',
        [int]$ExitCode = 0, [string]$Status = 'error', [switch]$Outage)
    $case = @{
        name = $Name; status = $Status; scanner = $Scanner; outage = [bool]$Outage
        hadolint = @{ json = '[]'; code = 0 }
        trivy = @{ json = $cleanTrivy; code = 0 }
    }
    $case[$Scanner] = @{ json = $Json; code = $ExitCode }
    return $case
}

$cases = @(
    New-Case -Name 'clean' -Status 'pass'
    New-Case -Name 'hadolint-warning' -Json $warning -ExitCode 1 -Status 'fail'
    New-Case -Name 'hadolint-error' -Json ($warning.Replace('warning', 'error')) -ExitCode 1 -Status 'fail'
    New-Case -Name 'hadolint-info' -Json ($warning.Replace('warning', 'info')) -Status 'pass'
    New-Case -Name 'hadolint-style' -Json ($warning.Replace('warning', 'style')) -Status 'pass'
    New-Case -Name 'trivy-high-vulnerability' -Scanner trivy -Json $highVuln -ExitCode 1 -Status 'fail'
    New-Case -Name 'trivy-critical-vulnerability' -Scanner trivy -Json ($highVuln.Replace('HIGH', 'CRITICAL')) -ExitCode 1 -Status 'fail'
    New-Case -Name 'trivy-high-misconfiguration' -Scanner trivy -Json $highMisconf -ExitCode 1 -Status 'fail'
    New-Case -Name 'trivy-low-vulnerability' -Scanner trivy -Json ($highVuln.Replace('HIGH', 'LOW')) -Status 'pass'
    New-Case -Name 'trivy-passed-check' -Scanner trivy -Json ($highMisconf.Replace('FAIL', 'PASS')) -Status 'pass'
    New-Case -Name 'hadolint-findings-exit-zero' -Json $warning
    New-Case -Name 'hadolint-clean-exit-one' -ExitCode 1
    New-Case -Name 'hadolint-info-exit-one' -Json ($warning.Replace('warning', 'info')) -ExitCode 1
    New-Case -Name 'trivy-vulnerability-exit-zero' -Scanner trivy -Json $highVuln
    New-Case -Name 'trivy-misconfiguration-exit-zero' -Scanner trivy -Json $highMisconf
    New-Case -Name 'trivy-clean-exit-one' -Scanner trivy -Json $cleanTrivy -ExitCode 1
    New-Case -Name 'trivy-low-exit-one' -Scanner trivy -Json ($highVuln.Replace('HIGH', 'LOW')) -ExitCode 1
    New-Case -Name 'invalid-json' -Json 'not-json'
    New-Case -Name 'wrong-root' -Json '{}'
    New-Case -Name 'empty-output' -Json ''
    New-Case -Name 'hadolint-null-item' -Json '[null]'
    New-Case -Name 'hadolint-missing-level' -Json '[{"code":"DL3000"}]'
    New-Case -Name 'hadolint-unknown-level' -Json '[{"code":"DL3000","level":"surprise"}]'
    New-Case -Name 'trivy-missing-results' -Scanner trivy -Json '{"SchemaVersion":2}'
    New-Case -Name 'trivy-null-results' -Scanner trivy -Json '{"SchemaVersion":2,"Results":null}'
    New-Case -Name 'trivy-object-results' -Scanner trivy -Json '{"SchemaVersion":2,"Results":{}}'
    New-Case -Name 'trivy-null-result' -Scanner trivy -Json '{"SchemaVersion":2,"Results":[null]}'
    New-Case -Name 'trivy-null-findings' -Scanner trivy -Json '{"SchemaVersion":2,"Results":[{"Vulnerabilities":null}]}'
    New-Case -Name 'trivy-missing-severity' -Scanner trivy -Json ($highVuln.Replace(',"Severity":"HIGH"', ''))
    New-Case -Name 'trivy-unknown-severity' -Scanner trivy -Json ($highVuln.Replace('HIGH', 'surprise'))
    New-Case -Name 'trivy-missing-status' -Scanner trivy -Json ($highMisconf.Replace(',"Status":"FAIL"', ''))
    New-Case -Name 'trivy-wrong-version' -Scanner trivy -Json '{"SchemaVersion":3,"Results":[]}'
    New-Case -Name 'hadolint-tool-error' -ExitCode 125
    New-Case -Name 'trivy-tool-error' -Scanner trivy -Json $cleanTrivy -ExitCode 125
    New-Case -Name 'outage' -Outage
    New-Case -Name 'clean-after-errors' -Status 'pass'
)
$results = @()

function docker {
    $scanner = 'trivy'
    if (@($args | Where-Object { $_ -like 'hadolint/hadolint:*' }).Count -gt 0) { $scanner = 'hadolint' }
    if ($args -notcontains '--read-only' -or $args -notcontains '--cap-drop=ALL') { throw 'Missing isolation flags' }
    if ($scanner -eq 'hadolint') {
        if ($args -notcontains '--failure-threshold' -or $args -notcontains 'warning') { throw 'Missing lint policy' }
    }
    elseif ($args -notcontains 'HIGH,CRITICAL' -or $args -notcontains 'vuln,misconfig' -or $args -notcontains '--exit-code') {
        throw 'Missing Trivy policy'
    }
    if ($scanner -eq 'trivy' -and $args -notcontains '/workspace/tests/fixtures') {
        throw 'Insecure fixtures must be scanned in isolation, not mixed into the baseline'
    }
    $global:SecurityGateTestCalls += $scanner
    if ($global:SecurityGateTestCase.outage) { throw 'Simulated Docker outage' }
    $global:LASTEXITCODE = $global:SecurityGateTestCase[$scanner].code
    Write-Output $global:SecurityGateTestCase[$scanner].json
}

try {
    foreach ($case in $cases) {
        $global:SecurityGateTestCase = $case
        $global:SecurityGateTestCalls = @()
        & (Join-Path $root 'scripts/Invoke-SecurityAudit.ps1') -RepositoryPath $fixture
        $code = $LASTEXITCODE
        $gate = Get-Content -LiteralPath (Join-Path $fixture '.evidence/gate.json') -Raw | ConvertFrom-Json
        $expectedCode = 1
        if ($case.status -eq 'pass') { $expectedCode = 0 }
        $ok = $code -eq $expectedCode -and $gate.status -eq $case.status -and -not $gate.ollamaUsedForGate
        $ok = $ok -and ($global:SecurityGateTestCalls -join ',') -eq 'hadolint,trivy'
        # Preserve raw child exit codes even when report validation fails.
        if (-not $case.outage) {
            $ok = $ok -and $gate.hadolint.exitCode -eq $case.hadolint.code -and $gate.trivy.exitCode -eq $case.trivy.code
            $expectedScannerStatus = 'error'
            if ($case.status -eq 'pass') { $expectedScannerStatus = 'pass' }
            elseif ($case.status -eq 'fail') { $expectedScannerStatus = 'findings' }
            $scannerResult = $gate.($case.scanner)
            $ok = $ok -and $scannerResult.status -eq $expectedScannerStatus
            if ($case.name -match 'exit-(zero|one)$') {
                $ok = $ok -and $scannerResult.reason -eq 'json-exit-code-mismatch'
            }
            if ($case.status -eq 'pass') { $ok = $ok -and $scannerResult.blockingFindings -eq 0 }
            elseif ($case.status -eq 'fail') { $ok = $ok -and $scannerResult.blockingFindings -eq 1 }
            $savedJson = Get-Content -LiteralPath (Join-Path $fixture ('.evidence/' + $case.scanner + '.json')) -Raw
            $ok = $ok -and $savedJson.Trim() -eq $case[$case.scanner].json.Trim()
        }
        $status = 'FAIL'
        if ($ok) { $status = 'PASS' }
        $results += [ordered]@{ name = $case.name; status = $status; expected = $case.status; observed = $gate.status; exitCode = $code }
        Write-Host "$status`: $($case.name)"
    }
    Remove-Item -LiteralPath (Join-Path $fixture 'Dockerfile')
    & (Join-Path $root 'scripts/Invoke-SecurityAudit.ps1') -RepositoryPath $fixture
    $code = $LASTEXITCODE
    $gate = Get-Content -LiteralPath (Join-Path $fixture '.evidence/gate.json') -Raw | ConvertFrom-Json
    $status = 'FAIL'
    if ($code -eq 1 -and $gate.status -eq 'error') { $status = 'PASS' }
    $results += [ordered]@{ name = 'missing-Dockerfile'; status = $status; expected = 'error'; observed = $gate.status; exitCode = $code }
}
finally {
    $results | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $fixture 'test-results.json') -Encoding UTF8
    Remove-Item Function:\docker
    Remove-Variable SecurityGateTestCase,SecurityGateTestCalls -Scope Global -ErrorAction SilentlyContinue
}
$failed = @($results | Where-Object { $_.status -ne 'PASS' }).Count
Write-Host "$($results.Count - $failed)/$($results.Count) contract tests passed. Evidence: $fixture/test-results.json"
if ($failed -gt 0) { exit 1 }
exit 0
