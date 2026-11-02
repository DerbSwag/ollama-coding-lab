# Ollama Coding Lab

Local AI coding assistant lab for Windows 11, Ollama, VS Code and Cline.
Ollama explains findings; **only static analysis determines the security gate**.

## Security audit pipeline

Work is isolated on `feature/security-audit-pipeline`, based on `main`.
The pipeline scans files without building the app, running `npm install`, executing
application code, deploying, or calling Ollama/cloud LLM APIs.

| Check | Blocking policy |
| --- | --- |
| Hadolint 2.14.0 | Root Dockerfile: warning/error findings fail |
| Trivy 0.76.1 filesystem scan | HIGH/CRITICAL vulnerabilities or misconfigurations fail |
| Missing input, Docker/download failure, empty/invalid report, unexpected exit code | Fail closed |
| Ollama response or availability | Never affects the gate |

Scanner digests are in `security-tools.json`; GitHub Actions use full commit SHAs.
Review version/digest updates together; do not replace pins with `latest`.
Containers mount the repo read-only, drop capabilities, have no Docker socket or
credential mounts, and use a read-only root filesystem. Hadolint has no network;
Trivy needs internet for databases/policy bundles and writes only to temporary storage.

The Dockerfile remains an audit exercise, not remediated. It uses `node:22-alpine`,
runs `npm install`, exposes port 3000 and starts `server.js`. No `package.json` or
`server.js` exists yet, so it cannot build a working app. Expect findings; do not
weaken the gate to make the example pass.

## Windows quick start

Prerequisites: Windows PowerShell 5.1 or PowerShell 7, Docker Desktop running in
Linux container mode, and internet access to registries/Trivy databases.
No native Hadolint/Trivy install or API key is required.

```powershell
Set-Location "$HOME\Projects\ollama-coding-lab"
docker version

# Allowlisted file hashes and PowerShell metadata; no LLM needed.
.\scripts\Collect-Evidence.ps1

# Optional running-model metadata from fixed loopback endpoints.
# Does not generate answers, download models, or determine security status.
.\scripts\Collect-Evidence.ps1 -IncludeOllama

# Real scanners: nonzero exit means findings or an operational error.
powershell -NoProfile -File .\scripts\Invoke-SecurityAudit.ps1
$LASTEXITCODE
Get-Content .\.evidence\gate.json

# Offline tests of clean/findings/error handling.
powershell -NoProfile -File .\tests\Test-SecurityGate.ps1
```

Do not globally disable execution policy; use your organization's approved
signing/execution process. PowerShell 7 users may replace `powershell` with `pwsh`.

## Evidence and coverage

`.evidence/` is ignored by Git. Every scan resets prior reports and writes:

| File | Contents |
| --- | --- |
| `environment.json` | UTC timestamp, PowerShell version, allowlisted SHA256 hashes; optional Ollama metadata |
| `hadolint.json` | Dockerfile lint findings |
| `trivy.json` | HIGH/CRITICAL filesystem vulnerability/misconfiguration findings |
| `gate.json` | Policy, scanner exit codes/status, final verdict, `ollamaUsedForGate: false` |

The collector does not dump environment variables, source code, chat history,
credentials, usernames, GPU process lists or Git remotes. Scanner reports can still
contain source excerpts/paths: review them before sharing or sending to an LLM.
Git ignore/scan exclusions are not an OS security boundary.

Trivy excludes `.git`, `.evidence`, `node_modules`, `.env*` and common key files.
Secret scanning is **not enabled**, avoiding raw secret matches in uploaded reports;
this does not prove absence of secrets. It scans the working tree, not Git history.
Dependency coverage requires supported manifests/lockfiles; this lab has none yet.
No built-image/base-image CVE scan, runtime test, exhaustive CI workflow audit, or
complete IaC validation is claimed. Hadolint covers only the root Dockerfile.
Add explicit coverage if more Dockerfiles are introduced. Unfixed vulnerabilities
are not exempted. Databases are downloaded into temporary storage on each real run.

## GitHub Actions and branch protection

`.github/workflows/security-audit.yml` runs for PRs to `main`, pushes to `main` or
`feature/security-audit-pipeline`, and manual dispatch. It tests gate handling,
collects evidence without Ollama, then runs scanners. Evidence upload runs after
failures, with an explicit four-file allowlist and 7-day retention. Artifacts are
visible to repository readers, including public repository readers. No scanner
secrets or GitHub write permissions are required.

No `pull_request_target`, privileged runner, deployment, `continue-on-error` or
success override is used. Cancelled/timed-out runs are not PASS and may have partial
evidence. Trivy repo config/ignore files are disabled for this gate.

After an approved push and first Actions run, configure GitHub rulesets/branch
protection to require **Static Analysis Gate** before merging into `main`.
Require review of pipeline/policy changes too. Adding a workflow alone does not
enforce merge protection. This implementation does not change GitHub settings or
publish a branch/PR automatically.

## Local AI review

Set Cline provider to `Ollama`, base URL `http://127.0.0.1:11434`, model `qwen3.5:4b`,
and manual approvals. Test 16K context before increasing it. Keep edits, terminal
execution and external tools unapproved during read-only review. Manually supply
reviewed, non-sensitive scanner findings and ask for file-referenced explanations.
AI recommendations never override the static verdict or GitHub job result.
Manual approvals and prompt rules do not provide an OS sandbox.

## Validation and change record

Implementation/validation: `docs/security-audits/2026-11-02-static-analysis-pipeline.md`.
Operational failure root causes and mitigations: `INCIDENTS.md`.
