# Compatible with Windows PowerShell 5.1 and PowerShell 7.
[CmdletBinding()]
param(
    [string]$RepositoryPath,
    [switch]$IncludeOllama
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $RepositoryPath) { $RepositoryPath = Split-Path -Parent $PSScriptRoot }
$root = (Resolve-Path -LiteralPath $RepositoryPath).Path
$output = Join-Path $root '.evidence'
New-Item -ItemType Directory -Path $output -Force | Out-Null

# Hash an explicit allowlist; never read environment variables, credentials,
# source file contents into the report, or arbitrary files recursively.
$relativePaths = @(
    'Dockerfile', 'README.md', '.gitignore', 'security-tools.json',
    'scripts/Collect-Evidence.ps1', 'scripts/Invoke-SecurityAudit.ps1',
    'tests/Test-SecurityGate.ps1', 'tests/Test-ScannerIntegration.ps1',
    'tests/fixtures/Dockerfile.insecure', '.dockerignore',
    '.github/workflows/security-audit.yml',
    'package.json', 'server.js', 'healthcheck.js', 'scripts/validate-container.mjs',
    'scripts/lib/validation.mjs', 'tests/api.test.mjs', 'tests/supply-chain.test.mjs'
)
$hashes = @(
    foreach ($relative in $relativePaths) {
        $path = Join-Path $root $relative
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            [ordered]@{ path = $relative; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
        }
    }
)
$report = [ordered]@{
    schemaVersion = 1
    collectedAtUtc = [DateTime]::UtcNow.ToString('o')
    powershellVersion = $PSVersionTable.PSVersion.ToString()
    files = $hashes
    ollama = [ordered]@{ requested = [bool]$IncludeOllama; status = 'not-requested' }
}
if ($IncludeOllama) {
    try {
        # Fixed loopback endpoint, no prompts or model downloads.
        $version = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/version' -TimeoutSec 5 -ErrorAction Stop
        $running = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/ps' -TimeoutSec 5 -ErrorAction Stop
        $report.ollama = [ordered]@{
            requested = $true
            status = 'available'
            version = $version.version
            runningModels = @($running.models | Select-Object name, size, size_vram, context_length)
        }
    }
    catch {
        # Do not copy raw exception text or system paths into evidence.
        $report.ollama = [ordered]@{ requested = $true; status = 'unavailable' }
    }
}
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $output 'environment.json') -Encoding UTF8
Write-Host 'Evidence saved to .evidence/environment.json (not a security verdict).'
