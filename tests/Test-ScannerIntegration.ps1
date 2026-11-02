# Real scanners: a rejected negative fixture is a passing enforcement test.
# The root policy verdict must independently be PASS. No LLM or app build.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$root = Split-Path -Parent $PSScriptRoot
$runDirectory = Join-Path $root ('.evidence/scanner-integration-' + [Guid]::NewGuid().ToString('N'))
$insecureDirectory = Join-Path $runDirectory 'insecure'
New-Item -ItemType Directory -Path $insecureDirectory -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'fixtures/Dockerfile.insecure') -Destination (Join-Path $insecureDirectory 'Dockerfile')
$results = @()
foreach ($case in @(
    @{ name = 'insecure-fixture'; path = $insecureDirectory; expected = 'fail'; code = 1 },
    @{ name = 'secure-baseline'; path = $root; expected = 'pass'; code = 0 }
)) {
    $code = $null
    $status = 'FAIL'
    $observed = 'error'
    try {
        & (Join-Path $root 'scripts/Collect-Evidence.ps1') -RepositoryPath $case.path
        & (Join-Path $root 'scripts/Invoke-SecurityAudit.ps1') -RepositoryPath $case.path
        $code = $LASTEXITCODE
        $gate = Get-Content -LiteralPath (Join-Path $case.path '.evidence/gate.json') -Raw | ConvertFrom-Json
        $observed = $gate.status
        $ok = $code -eq $case.code -and $gate.status -eq $case.expected -and -not $gate.ollamaUsedForGate
        $ok = $ok -and $gate.hadolint.status -eq 'pass' -and $gate.hadolint.exitCode -eq 0
        $ok = $ok -and $gate.hadolint.blockingFindings -eq 0 -and $gate.hadolint.reason -eq 'consistent'
        $ok = $ok -and $gate.trivy.reason -eq 'consistent'
        if ($case.name -eq 'insecure-fixture') {
            $trivy = Get-Content -LiteralPath (Join-Path $case.path '.evidence/trivy.json') -Raw | ConvertFrom-Json
            $rootFindings = @(
                foreach ($result in $trivy.Results) {
                    $property = $result.PSObject.Properties['Misconfigurations']
                    if ($null -ne $property) {
                        $property.Value | Where-Object { $_.ID -eq 'DS-0002' -and $_.Severity -eq 'HIGH' -and $_.Status -eq 'FAIL' }
                    }
                }
            )
            $ok = $ok -and $rootFindings.Count -eq 1 -and $gate.trivy.status -eq 'findings'
            $ok = $ok -and $gate.trivy.exitCode -eq 1 -and $gate.trivy.blockingFindings -eq 1
        }
        else {
            $ok = $ok -and $gate.trivy.status -eq 'pass' -and $gate.trivy.exitCode -eq 0
            $ok = $ok -and $gate.trivy.blockingFindings -eq 0
        }
        if ($ok) { $status = 'PASS' }
    }
    catch {
        Write-Warning "$($case.name): scanner evidence unavailable or invalid."
    }
    $results += [ordered]@{
        name = $case.name; status = $status; expectedGate = $case.expected
        observedGate = $observed; gateExitCode = $code
    }
    Write-Host "$status`: $($case.name) (gate: $observed)"
}
$results | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $runDirectory 'test-results.json') -Encoding UTF8
Write-Host "Integration evidence: $runDirectory"
if (@($results | Where-Object { $_.status -ne 'PASS' }).Count -gt 0) { exit 1 }
exit 0
