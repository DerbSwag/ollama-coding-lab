# Incidents

## 2026-11-02: Git commit identity unavailable

- Problem: the first local commit failed with `Author identity unknown`.
- Root cause: Git had no usable configured author identity at the failed commit.
- Mitigation: keep work on the feature branch and request author name/email before
  configuring repository-local identity and committing. Do not invent an author or
  change global configuration. No push was performed.
- Resolution: user supplied the author identity explicitly. Repository-local
  `user.name` and `user.email` were set, and `git var GIT_AUTHOR_IDENT` and
  `git var GIT_COMMITTER_IDENT` both returned the requested identity.

## 2026-11-02: PowerShell 5.1 parameter default failed

- Problem: initial collector/audit scripts failed because `$PSScriptRoot` was empty
  while evaluating a parameter default in the tested Windows PowerShell invocation.
- Root cause: resolving script location during parameter-default evaluation.
- Mitigation: resolve the default repository directory in the script body after
  parameter binding; verify the collector and gate contracts with PowerShell 5.1.

## 2026-11-02: Linux validation image tag unavailable

- Problem: the test-only PowerShell image tag `7.4-ubuntu-24.04` was not found.
- Root cause: the assumed version/OS tag is not published by Microsoft.
- Mitigation: query Microsoft's registry tag list, use the available
  `7.5-ubuntu-24.04` image and rerun Linux contract tests. This test image is not a
  dependency of the committed workflow, which uses the hosted runner's `pwsh`.

## 2026-11-02: Security gate accepted inconsistent scanner evidence

- Problem: baseline gate could return PASS for valid JSON containing blocking
  findings when the child exit code was 0. Incomplete Trivy report shapes could
  also pass. Reproduced using synthetic Docker responses, not production data.
- Confirmed root cause: superficial JSON validation followed by status assignment
  from exit code alone; JSON findings were not evaluated against the blocking policy.
- Mitigation: validate report/finding shapes, count policy-relevant findings and
  compare them against exit 0/1. Contradictions produce `error` and overall exit 1.
  Preserve raw exit codes/stdout, add counts/reasons, and run 37 regression contracts
  on PowerShell 5.1 and 7.5. Real integration retains the expected HIGH root-user
  finding and fails the gate. Evidence and limitations are recorded under
  `JSON and exit-code hardening` in the static analysis audit document.
- Residual risk: GitHub-hosted execution/branch protection remain unverified;
  scanner/database trust and existing Dockerfile findings remain outside this fix.

## 2026-11-02: Phase 1 expected root-user policy rejection

- Problem: remote run 41477039945 failed its policy step with HIGH `DS-0002`, as
  expected. This verified enforcement rather than indicating a broken harness.
- Confirmed cause: the example Dockerfile omitted a non-root runtime USER.
- Mitigation: Phase 2 root baseline adds `USER node` and owned source copies;
  preserve the original under isolated negative fixtures. Real integration verifies
  insecure fail/1 and root baseline pass/0 without suppressing DS-0002 or lowering
  severity. Build/runtime and Phase 2 remote validation remain pending.

## 2026-11-02: Matrix shell expression rejected by actionlint

- Problem: actionlint rejected matrix context in a step-level `shell` expression.
- Root cause: matrix shell selection was placed at the unsupported step context.
- Mitigation: move shell expression to job-level `defaults.run.shell`; local
  actionlint then exited 0. No failing workflow was pushed.

## 2026-11-03: GitHub Actions Node20 runtime warning

- Problem: PR #1 reported Node20 deprecation warnings despite successful checks.
- Confirmed cause: pinned checkout v4.3.1 and upload-artifact v4.6.2 metadata both
  declare node20. This is a maintenance warning, not a proven security exploit.
- Mitigation: update four references to SHA-pinned checkout v7.0.1 and
  upload-artifact v7.0.2, both declaring node24; validate inputs and unchanged
  workflow semantics with metadata checks and actionlint. Fresh hosted execution
  and confirmation that warnings disappear remain pending approved push.

## 2026-11-03: Docker daemon unavailable for workflow lint

- Problem: Docker-based actionlint could not find the Docker Desktop Linux pipe.
- Confirmed cause: the daemon endpoint was unavailable in this session.
- Mitigation: download the official actionlint 1.7.7 Windows release into ignored
  local evidence, verify its published SHA256 checksum, and run the standalone
  validator. Exit 0; no daemon start or system-wide installation performed.

## 2026-11-03: Phase 3 bundled package-manager CVEs

- Problem: first real image scan found six HIGH vulnerabilities and correctly
  failed validation despite successful build/runtime/SBOM checks.
- Confirmed cause: brace-expansion 5.0.9 and undici 6.28.0 in the official base's
  bundled npm dependency tree; not dependencies of the demo application.
- Mitigation: remove unused npm/Yarn/Corepack in a preparation stage and copy the
  cleaned filesystem into the final stage, so vulnerable files are absent from
  final layers. Rescan found 0 blocking HIGH/CRITICAL findings without exceptions.
- All six remediated CVEs and before/after evidence are listed under
  `Confirmed vulnerability remediation` in the Phase 3 audit document.

## 2026-11-03: Local test sandbox and guessed image tag

- Observed errors: initial local node:test process spawning returned EPERM in the
  restricted sandbox; guessed official tag 24.14.0-alpine3.24 was not found.
- Mitigation: run authorized tests with child-process/localhost access; resolve
  the published node:24-alpine digest, then verify actual Node 24.22.2 inside it.
  No failed test is recorded as PASS, and no guessed tag was used for the build.

## 2026-11-03: Docker OCI identity differs from scanner configuration digest

- Observation: Docker containerd store returns an OCI index digest while Trivy
  reports a different image configuration digest for the same exported image.
- Confirmed explanation: archive index, config blob and runtime rootfs DiffIDs
  were inspected; the IDs refer to different OCI object types, not different code.
- Mitigation: verify runtime layer DiffIDs and unique ownership label against
  SBOM/scan, match SBOM config digest to scan config digest, and hash the exact
  exported archive. Regression cases reject foreign run/layer metadata.
