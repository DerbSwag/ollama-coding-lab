# Ollama Coding Lab

Local AI coding assistant lab for Windows 11, Ollama, VS Code and Cline.
Ollama explains findings; **only static analysis determines the security gate**.

## Security audit pipeline

Phase 3 is isolated on `feature/container-runtime-supply-chain`, based on verified
`main` commit `6677200`. The original Phase 1-2 jobs scan files without building or
executing the app. Phase 3 adds a separate container runtime/supply-chain job.
Neither path deploys, uses `npm install`, or calls Ollama/cloud LLM APIs.

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

The root Dockerfile uses `USER node` and copies source with `--chown=node:node`.
The original root-user example is preserved in
`tests/fixtures/Dockerfile.insecure` for real negative enforcement tests.
`.dockerignore` excludes local evidence, credentials, dependency directories and
test/documentation files from the build context.

Phase 3 includes a minimal dependency-free Node HTTP API, digest-pinned multi-stage
image, functional healthcheck, runtime checks, CycloneDX SBOM and HIGH/CRITICAL image
vulnerability enforcement. No external npm dependencies are declared or installed;
no lockfile is needed for this dependency-free build. This is a demonstration, not
a production service or security certification.

## Windows quick start

Prerequisites: Windows PowerShell 5.1 or PowerShell 7, Docker Desktop running in
Linux container mode, and internet access to registries/Trivy databases.
No native Hadolint/Trivy install or API key is required.
Phase 3 also requires host Node.js 22+ (24 recommended) and Linux/amd64 Docker support.

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

# Real scanners: verify fixture rejection AND root baseline acceptance.
powershell -NoProfile -File .\tests\Test-ScannerIntegration.ps1
$LASTEXITCODE

# Phase 3 API, process failure and image-policy/provenance tests.
node --test tests/api.test.mjs tests/supply-chain.test.mjs

# Build, verify runtime/recovery, generate SBOM and enforce image policy.
node scripts/validate-container.mjs
$LASTEXITCODE
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

Contract tests save individual results under `.evidence/gate-test-*/test-results.json`.
Real integration tests copy the insecure fixture into an isolated root Dockerfile
under `.evidence/scanner-integration-*/insecure/` and retain its four evidence files
in that directory's `.evidence/`. The integration summary lives alongside
`insecure/` as `test-results.json`. The secure case scans the real repository and
writes the standard root evidence. Both cases are attempted; any unmet expectation
or scanner error returns integration exit 1. Negative test PASS requires gate
`fail/1`, exactly one HIGH `DS-0002`, and consistent scanner evidence. Secure test
PASS requires gate `pass/0` with no blockers. This does not override either verdict.

The collector does not dump environment variables, source code, chat history,
credentials, usernames, GPU process lists or Git remotes. Scanner reports can still
contain source excerpts/paths: review them before sharing or sending to an LLM.
Git ignore/scan exclusions are not an OS security boundary.

Trivy excludes `.git`, `.evidence`, `node_modules`, `.env*` and common key files.
The only intentional-example exclusion is `/workspace/tests/fixtures`; fixtures
are copied outside that path and scanned as a root Dockerfile by the integration
test. No severity threshold or rule is disabled. New production files must not be
placed under the fixture directory.
Secret scanning is **not enabled**, avoiding raw secret matches in uploaded reports;
this does not prove absence of secrets. It scans the working tree, not Git history.
The demo manifest declares no external dependencies. Filesystem scanning is not
image coverage: Phase 3 separately scans the exported image. Exhaustive CI workflow
auditing and complete IaC validation are not claimed. Hadolint covers only the root Dockerfile.
Add explicit coverage if more Dockerfiles are introduced. Unfixed vulnerabilities
are not exempted. Databases are downloaded into temporary storage on each real run.

## GitHub Actions and branch protection

`.github/workflows/security-audit.yml` runs for PRs to `main`, pushes to `main` or
`feature/security-audit-pipeline`, and manual dispatch. Separate jobs run the 37
offline contracts on Windows PowerShell 5.1 (`windows-2022`) and PowerShell 7
(`ubuntu-24.04`), then enforce real positive/negative scanner integration on Ubuntu.
Pushes to `feature/container-runtime-supply-chain` also trigger validation.
The new Container Runtime and Supply Chain job explicitly requires Static Analysis
Gate success; it cannot replace or override the original jobs.
The policy job runs even after contract failure and explicitly requires the matrix
result to be `success`; a failed prerequisite cannot become a skipped green gate.

Contract result JSON and explicitly allowlisted positive/negative scan evidence
are uploaded with `always()`, including failed test/scan runs, with 7-day retention.
Cancelled runs or failures before evidence creation can have incomplete artifacts.
Artifacts are visible to repository readers, including public readers. No scanner
secrets or GitHub write permissions are required.

No `pull_request_target`, privileged runner, deployment, `continue-on-error` or
success override is used. Cancelled/timed-out runs are not PASS and may have partial
evidence. Trivy repo config/ignore files are disabled for this gate.

After an approved Phase 2 push and Actions run, configure GitHub rulesets/branch
protection to require **Static Analysis Gate** before merging into `main`.
After Phase 3 hosted validation, require **Container Runtime and Supply Chain** as
an additional check; a passing static-only check does not imply runtime acceptance.
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
Phase 1 enforcement was verified remotely in [run 41477039945](https://github.com/DerbSwag/ollama-coding-lab/actions/runs/41477039945)
at commit `d4a0d9c`: the job failed on the intentionally root-user Dockerfile, and
evidence upload succeeded. This expected rejection is not a green CI run.
Phase 2 changes/results: `docs/security-audits/2026-11-02-phase2-merge-ready-pipeline.md`.
Phase 2 at `0b2e1d4` passed the [PR workflow](https://github.com/DerbSwag/ollama-coding-lab/actions/runs/41653749463)
with all three jobs and artifact uploads successful. The subsequent Node24 refresh
at `49cf25a` passed push/PR runs and review, then PR #1 was squash-merged as `6677200`.
Review history: `docs/security-audits/2026-11-03-final-review-node24-actions.md`.
Operational failure root causes and mitigations: `INCIDENTS.md`.

## Phase 3: demo container and supply chain

`GET /` returns service/version JSON; `GET /health` returns HTTP 200 and
`{"status":"ok"}`. Unknown GET routes return 404, unsupported methods return 405
with `Allow: GET`, and malformed URLs return 400. SIGTERM/SIGINT close the server
gracefully with a bounded drain period. Default port is 3000; invalid PORT exits 1.

The Dockerfile pins the official Node 24 image by digest. A preparation stage
removes unused npm/Yarn/Corepack; the final `scratch` stage copies that cleaned
Alpine/Node filesystem, including libraries and the node user. The final image
still contains Alpine; `scratch` here does not mean a static binary or distroless
image. Explicit COPY includes only package.json, server.js and healthcheck.js.
Removed vulnerable packages are absent from final image layers, not just hidden
by an ignore rule. No npm installation or package-manager runtime is required.

Validation uses an ephemeral port on **127.0.0.1 only**, non-root UID 1000,
read-only root, all capabilities dropped, no-new-privileges and bounded memory/PIDs.
It verifies effective kernel state, HTTP/container health, EROFS on a write probe,
failed startup, failed health probe, SIGTERM/SIGINT and stop/start recovery. The API
listens on 0.0.0.0 inside the container; Docker enforces the host publish restriction.

Each run writes `.evidence/phase3-<UUID>/phase3.json`, `sbom.cdx.json`,
`image-vulnerabilities.json` and command stdout/stderr/exit records. Source hashes,
Docker image identity, archive SHA256, rootfs DiffIDs, SBOM config digest and run
labels are verified together. Trivy receives only a read-only image archive and
dedicated cache, never the host Docker socket. HIGH/CRITICAL findings, inconsistent
reports, scanner errors and unverifiable controls cannot produce overall PASS.

Only exact run-specific container names with matching ownership labels are removed.
Images and local archives/caches remain for review/rollback. CI uploads JSON/SBOM
evidence with 7-day retention, excluding archives/caches. Review evidence for paths
and metadata before sharing. Abrupt termination or engine loss may require manual
cleanup of the exact recorded owned names.

Validated locally on Windows/Docker Desktop; Phase 3 hosted CI is **NOT_RUN** until
an explicitly authorized push. See [RUNBOOK.md](RUNBOOK.md) and
`docs/security-audits/2026-11-03-phase3-container-runtime-supply-chain.md` for commands,
results, image/SBOM identities, limitations and rollback procedures.
