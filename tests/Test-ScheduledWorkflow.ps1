Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$workflowPath = Join-Path $root '.github/workflows/scheduled-security-scan.yml'
$workflow = Get-Content -LiteralPath $workflowPath -Raw
$assertions = @(
    @{ name = 'Sunday 02:17 UTC schedule'; pattern = "cron:\s*'17 2 \* \* 0'" },
    @{ name = 'PRs targeting main trigger workflow contracts'; pattern = '(?s)pull_request:\s*\r?\n\s+branches:\s*\[main\].*workflow-contracts:' },
    @{ name = 'manual trigger'; pattern = '(?m)^\s+workflow_dispatch:\s*$' },
    @{ name = 'read-only permissions'; pattern = '(?s)permissions:\s*\r?\n\s+contents:\s*read' },
    @{ name = 'separate concurrency group'; pattern = 'group:\s*scheduled-security-scan-\$\{\{ github\.ref \}\}' },
    @{ name = 'do not cancel active scan'; pattern = 'cancel-in-progress:\s*false' },
    @{ name = 'reuse existing gate'; pattern = 'scripts/Invoke-SecurityAudit\.ps1' },
    @{ name = 'contract job runs PowerShell on Ubuntu'; pattern = '(?s)workflow-contracts:\s*\r?\n.*?runs-on:\s*ubuntu-[^\r\n]+.*?shell:\s*pwsh.*?Test-ScheduledWorkflow\.ps1' },
    @{ name = 'full scan waits for passing contract job'; pattern = '(?s)security-scan:\s*\r?\n.*?needs:\s*workflow-contracts.*?if:\s*\$\{\{\s*needs\.workflow-contracts\.result\s*==\s*''success''\s*&&\s*\(github\.event_name\s*==\s*''schedule''\s*\|\|\s*github\.event_name\s*==\s*''workflow_dispatch''\)\s*\}\}' },
    @{ name = 'full scan excludes pull request events'; pattern = '(?s)security-scan:\s*\r?\n.*?if:\s*\$\{\{.*github\.event_name\s*==\s*''schedule''.*github\.event_name\s*==\s*''workflow_dispatch''.*\}\}.*?Run static security gate' },
    @{ name = 'always upload evidence'; pattern = 'if:\s*\$\{\{ always\(\) \}\}' },
    @{ name = 'missing evidence fails'; pattern = 'if-no-files-found:\s*error' },
    @{ name = 'seven day retention'; pattern = 'retention-days:\s*7' },
    @{ name = 'checkout pinned by full SHA'; pattern = 'actions/checkout@[0-9a-f]{40}' },
    @{ name = 'artifact action pinned by full SHA'; pattern = 'actions/upload-artifact@[0-9a-f]{40}' }
)
foreach ($assertion in $assertions) {
    if ($workflow -notmatch $assertion.pattern) { throw "Contract failed: $($assertion.name)" }
    Write-Host "PASS: $($assertion.name)"
}
if ($workflow -match 'write|secrets\.') { throw 'Unexpected write permission or secret reference.' }
Write-Host "$($assertions.Count) scheduled workflow contracts passed."
