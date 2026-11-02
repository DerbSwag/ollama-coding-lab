# Phase 2: merge-ready security pipeline

## Scope and baseline

Continue `feature/security-audit-pipeline` from `d4a0d9c`; preserve both Phase 1
commits and its verified remote enforcement run 41477039945. Produce a separate
Phase 2 commit. No deployment, application build, rule suppression or LLM verdict.

## Remediation Implemented

- Resolve the root Dockerfile's default-root runtime (`DS-0002`) by adding
  `USER node`; use `COPY --chown=node:node` for copied source. Add `.dockerignore`
  for credentials, local evidence, dependencies, tests and documentation.
- Preserve the original insecure Dockerfile in `tests/fixtures/Dockerfile.insecure`.
  Exclude only this intentional fixture directory from the main Trivy scan; copy
  the fixture to an isolated root Dockerfile and explicitly scan it with the same
  pinned tools and unchanged blocking policy. No production source belongs there.
- Add `Test-ScannerIntegration.ps1`: attempt both cases, require exactly one HIGH
  failing `DS-0002` for the negative case with gate fail/1, and no blockers with
  gate pass/0 for the root baseline. Require consistent scanner statuses/reasons.
  Any unexpected result/error returns harness exit 1. Never rewrite gate verdicts.
- Extend collector hash allowlist to include integration script, fixture and
  `.dockerignore`; optional Ollama behavior remains excluded from gate decisions.
- Separate offline contract matrix (Windows PowerShell 5.1 and PowerShell 7/Linux)
  from real policy enforcement in GitHub Actions. Explicitly fail the policy job
  if its required contract matrix did not succeed, rather than silently skip it.
- Upload contract JSON plus explicit positive/negative scan report allowlists on
  success or failure with 7-day retention. No token permission or scanner pin changes.
- Update README coverage, commands, non-production limits and Phase 1 remote status.

## Validation and evidence

- Windows PowerShell 5.1: PASS, 37/37 contracts, exit 0.
  `.evidence/phase2-contracts-ps51.log` and
  `.evidence/gate-test-81e8314987f0438fbd24cd442677eb7a/test-results.json`.
- PowerShell 7.5 / Ubuntu 24.04: PASS, 37/37 contracts, exit 0.
  `.evidence/phase2-contracts-ps7.log` and
  `.evidence/gate-test-34bcbd04c6bc494988a2f977d90fb655/test-results.json`.
- Real integration on PowerShell 5.1 / Docker Desktop: PASS, 2/2 cases, exit 0.
  `.evidence/scanner-integration-fa9cb91218ee4b8abf2a0978ea80f097/test-results.json`.
  Negative case gate fail/1, one HIGH failing DS-0002, retained under
  `insecure/.evidence/` inside that directory. Root baseline gate pass/0, both
  scanners pass/0, zero blockers, `reason: consistent`, `ollamaUsedForGate: false`.
  Root evidence: `.evidence/{environment,gate,hadolint,trivy}.json`.
- actionlint 1.7.7: PASS, exit 0 after correcting matrix shell context placement.
  Job-level `defaults.run.shell` selects matrix shell; step-level matrix shell
  expressions were rejected during the first local check and corrected.
- Workflow prerequisite guard: PASS, 4/4 states. Actual PowerShell execution
  returns 0 for `success` and nonzero for `failure`, `cancelled` and `skipped`.
  Evidence: `.evidence/phase2-workflow-guard.json`. SHA pins/read-only permissions
  and lack of `continue-on-error` were also checked. Original fixture instructions
  match `d4a0d9c:Dockerfile` after explicitly decoding UTF-8 and normalizing its BOM.
- Phase 2 GitHub-hosted run, remote artifact retention/upload, PR and branch
  protection: NOT_RUN/unverified pending approval to push the new commit.

Evidence is local and ignored by Git. Phase 1 remote artifacts and Phase 2 local
results must not be conflated. No new GitHub write has been performed in this phase.

## Residual risks and acceptance limits

Static secure baseline only: `package.json`, lockfile and `server.js` are absent.
No working app can be built yet. No dependency installation, permission/write-path
runtime tests, health checks or image/base-image CVE scan ran. Secret scanning and
Git-history scanning remain outside coverage. Passing local scans is not proof
of production readiness or a green GitHub-hosted Phase 2 workflow.

## Rollback and next actions

After review, revert the separate Phase 2 commit to restore `d4a0d9c`; this restores
the intentionally failing root-user baseline. Do not reset/clean user work.
Rollback was not executed. Approve feature-branch push, verify the new GitHub run
and both artifact types, then open/review a PR to main and configure required checks.
