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
