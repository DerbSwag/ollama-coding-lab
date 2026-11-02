# Mock the Docker process boundary; no Docker, Ollama or network required.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$fixture = Join-Path $root ('.evidence/gate-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture -Force | Out-Null
Set-Content -LiteralPath (Join-Path $fixture 'Dockerfile') -Value 'FROM scratch' -Encoding UTF8

function docker {
    $isHadolint = @($args | Where-Object { $_ -like 'hadolint/hadolint:*' }).Count -gt 0
    if ($args -notcontains '--read-only' -or $args -notcontains '--cap-drop=ALL') { throw 'Missing isolation flags' }
    $global:LASTEXITCODE = 0
    if ($global:SecurityGateTestScenario -eq 'outage') { throw 'Simulated Docker outage' }
    if ($global:SecurityGateTestScenario -eq 'invalid-json') { Write-Output 'not-json'; return }
    if ($global:SecurityGateTestScenario -eq 'wrong-schema') { Write-Output '{}'; return }
    if ($global:SecurityGateTestScenario -eq 'empty-output') { return }
    if ($global:SecurityGateTestScenario -eq 'tool-error') { $global:LASTEXITCODE = 125 }
    if ($isHadolint) {
        if ($args -notcontains '--failure-threshold' -or $args -notcontains 'warning') { throw 'Missing lint threshold' }
        if ($global:SecurityGateTestScenario -eq 'hadolint-findings') { $global:LASTEXITCODE = 1 }
        Write-Output '[]'
    }
    else {
        if ($args -notcontains 'HIGH,CRITICAL' -or $args -notcontains 'vuln,misconfig' -or $args -notcontains '--exit-code') {
            throw 'Missing Trivy gate policy'
        }
        if ($global:SecurityGateTestScenario -eq 'trivy-findings') { $global:LASTEXITCODE = 1 }
        Write-Output '{"SchemaVersion":2,"Results":[]}'
    }
}

try {
    foreach ($case in @(
        @{ name = 'clean'; status = 'pass'; code = 0 },
        @{ name = 'hadolint-findings'; status = 'fail'; code = 1 },
        @{ name = 'trivy-findings'; status = 'fail'; code = 1 },
        @{ name = 'invalid-json'; status = 'error'; code = 1 },
        @{ name = 'wrong-schema'; status = 'error'; code = 1 },
        @{ name = 'empty-output'; status = 'error'; code = 1 },
        @{ name = 'tool-error'; status = 'error'; code = 1 },
        @{ name = 'outage'; status = 'error'; code = 1 }
    )) {
        $global:SecurityGateTestScenario = $case.name
        & (Join-Path $root 'scripts/Invoke-SecurityAudit.ps1') -RepositoryPath $fixture
        $code = $LASTEXITCODE
        $gate = Get-Content -LiteralPath (Join-Path $fixture '.evidence/gate.json') -Raw | ConvertFrom-Json
        if ($code -ne $case.code -or $gate.status -ne $case.status -or $gate.ollamaUsedForGate) {
            throw "Gate contract failed: $($case.name)"
        }
        Write-Host "PASS: $($case.name)"
    }
    Remove-Item -LiteralPath (Join-Path $fixture 'Dockerfile')
    $global:SecurityGateTestScenario = 'clean'
    & (Join-Path $root 'scripts/Invoke-SecurityAudit.ps1') -RepositoryPath $fixture
    $code = $LASTEXITCODE
    $gate = Get-Content -LiteralPath (Join-Path $fixture '.evidence/gate.json') -Raw | ConvertFrom-Json
    if ($code -ne 1 -or $gate.status -ne 'error') { throw 'Missing input did not fail closed' }
    Write-Host 'PASS: missing Dockerfile'
}
finally {
    Remove-Item Function:\docker
    Remove-Variable SecurityGateTestScenario -Scope Global
}
Write-Host 'All 9 security gate contract tests passed. Test evidence remains under .evidence/.'
exit 0
