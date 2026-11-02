# Static analysis pipeline implementation

## Scope

Feature branch `feature/security-audit-pipeline` based on existing `main`.
Add evidence collection and a deterministic static analysis gate. Retain the
existing Dockerfile exercise. No application remediation or production certification.

## Remediation Implemented

- Add PowerShell 5.1/7 evidence collector with allowlisted SHA256 metadata and
  optional loopback Ollama metadata; no chat generation or credential dump.
- Add digest-pinned Hadolint/Trivy containers with read-only repository mounts,
  dropped capabilities, no privileged mode and no host Docker socket mount.
- Fail for Hadolint warning/error, Trivy HIGH/CRITICAL vulnerabilities or
  misconfigurations, and scanner/prerequisite/report errors. Reset stale evidence.
  Ollama never participates in the verdict.
- Add GitHub Actions with SHA-pinned checkout/upload, read-only contents permission,
  disabled credential persistence, PR/push/manual triggers, failure evidence upload
  and 7-day retention. No GitHub write or branch protection changes performed.
- Ignore local evidence and common credentials in Git. Exclude credential patterns
  and generated/dependency directories from Trivy. Secret scanning is not enabled;
  review scanner reports before sharing.
- Add offline gate contract tests, README setup/policy/coverage/branch-protection
  instructions and incident notes. Preserve the original Dockerfile unchanged.

## Validation

- Nine offline gate contract tests passed on Windows PowerShell 5.1 and
  PowerShell 7.5 on Ubuntu 24.04: clean result, either scanner's findings,
  malformed JSON, wrong schema, empty output, unexpected tool exit, Docker outage,
  and missing Dockerfile. Sequential tests also exercise replacement of old reports.
- Real digest-pinned scanners completed on Docker Desktop: Hadolint exit 0 with
  no findings; Trivy exit 1 with HIGH `DS-0002` (default root user). The gate exited
  1 with status `fail`, as intended. The Dockerfile was not remediated or suppressed.
- Collector completed with and without optional Ollama metadata. Eight allowlisted
  files were hashed. Optional loopback metadata was available; no chat was generated.
- GitHub Actions YAML parsed, workflow policy assertions passed, and actionlint
  1.7.7 exited 0. Git diff whitespace checks passed.
- Dockerfile SHA256 remains
  `CCDB80D2858EBB700C7BD50E94E7328594E0B71EEC271405F41EBA3D867B5D6A`.
- GitHub Actions execution and branch protection remain unverified; no push or
  GitHub write occurred. User explicitly supplied the commit identity;
  repository-local configuration and both author/committer identities were verified.

Evidence is local under `.evidence/` and intentionally excluded from Git.

## Limits and follow-up

Only the root Dockerfile is linted. Trivy scans the working tree, not built images
or Git-history secrets. No Node manifests/lockfiles exist yet. Findings depend on
current databases and policies. Dockerfile findings are intentionally not suppressed.
Protect `Static Analysis Gate` and policy/workflow changes on GitHub after review.

## JSON and exit-code hardening

Baseline: `267a94e6b973ce39cb25cfc332b30e9073959408`. Retain this implementation
commit unchanged; add a separate hardening commit on the same feature branch.

### Confirmed root cause

The baseline validated JSON superficially, then assigned scanner status from exit
code alone. A synthetic Hadolint warning or Trivy HIGH finding combined with exit
0 produced PASS. Conversely, exit 1 with no blocking findings was labelled a
finding instead of inconsistent evidence. The baseline also accepted incomplete
Trivy reports such as `{"SchemaVersion":2}` and malformed finding entries.

This was reproduced with the real gate script and mocked Docker output before
changing gate logic: only 15/37 new contracts passed. Red evidence:
`.evidence/gate-test-c33f718d29034c77ba20f46d9b77ae51/test-results.json`.
These are deliberately contradictory synthetic reports, not evidence that a real
Hadolint or Trivy release emitted incorrect exit codes.

### Remediation Implemented

- Count blocking Hadolint warning/error findings and Trivy HIGH/CRITICAL
  vulnerabilities or failing misconfiguration checks directly from validated JSON.
- Require exit 0 with zero blocking findings for PASS, or exit 1 with blocking
  findings for the `findings` status. Any contradiction becomes `error` with
  `reason: json-exit-code-mismatch`; overall exit is 1. Unexpected exit codes,
  malformed shapes, missing fields and unknown severity/level/status fail closed.
- Preserve raw scanner exit codes and stdout for diagnosis, including invalid
  reports. Add `blockingFindings` and `reason` to per-scanner gate evidence.
- Preserve arrays across PowerShell 5.1/7 parsing with a JSON wrapper. Enforce
  Trivy schema version 2 with an explicit Results array; optional finding arrays
  may be absent, but if present must be arrays. Valid low-priority findings and
  PASS/EXCEPTION misconfiguration records do not block.
- Expand isolated contracts from 9 to 37 cases. Assert both scanners execute,
  verdict/overall exit agree, raw child exit codes and stdout are retained,
  mismatch reasons are recorded, and stale PASS does not survive errors.
- Only security gate logic/tests and existing audit/incident documentation change.
  Dockerfile, workflow, scanner pins, synthetic isolation and Ollama exclusion
  remain unchanged. No push, PR, production action or GitHub setting change.

### Validation and evidence

- Windows PowerShell 5.1: PASS, 37/37, exit 0.
  `.evidence/hardening-powershell51.log` and
  `.evidence/gate-test-17451d9405dd4895a03a416d649941b7/test-results.json`.
- PowerShell 7.5 / Ubuntu 24.04: PASS, 37/37, exit 0.
  `.evidence/hardening-powershell7.log` references its isolated JSON results.
- actionlint 1.7.7: PASS, exit 0, on the unchanged workflow.
- Real scanner integration: Hadolint exit 0, zero blockers, `reason: consistent`;
  Trivy exit 1, one HIGH `DS-0002` blocker, `reason: consistent`. Overall `fail`,
  exit 1, as required. Evidence: `.evidence/gate.json`, `.evidence/hadolint.json`,
  `.evidence/trivy.json`. The existing root-user issue is not remediated here.
- Real scanner integration ran on Windows PowerShell 5.1 / Docker Desktop;
  PowerShell 7 exercised mocked contracts on Linux, not real scanner processes.
- GitHub-hosted execution and required-check branch protection: NOT_RUN/unverified.
  Local ignored evidence is not included in the hardening commit.

Rollback: revert the separate hardening commit after review to restore the baseline
logic and tests. No rollback executed; baseline false-PASS risk would return.
