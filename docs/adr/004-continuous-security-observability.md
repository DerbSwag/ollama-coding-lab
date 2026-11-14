# ADR-004: Continuous Security Monitoring with Existing Tooling

**Status:** Proposed for implementation
**Baseline:** `c506abb5056022bd3f0b615c797567abd3478d71`
**Scope:** Phase 4 / PR #3 — Scheduled Security Scan

## Context

The repository already has GitHub Actions security validation, Trivy scanning,
SHA-pinned GitHub Actions, and evidence artifacts with seven-day retention. The
current security workflow supports push, pull request, and manual execution but
does not have a scheduled trigger.

## Decision

1. Run a scheduled security scan every Sunday at 02:17 UTC (09:17 Asia/Bangkok).
2. Reuse the existing scanner implementation and HIGH/CRITICAL vulnerability policy.
3. Keep scheduled execution isolated from PR and push CI to avoid unintended cancellation.
4. Keep `contents: read` permissions and pin third-party Actions to full commit SHAs.
5. Retain evidence artifacts for seven days, including failed validation runs.
6. Treat scanner unavailability, invalid results, or missing evidence as failure.
7. Use GitHub Actions run status and native notifications as the initial alert mechanism.
8. Add no npm dependencies, external monitoring services, secrets, or application runtime changes.

## Constraints and trade-offs

- Scheduled workflows may not start at the exact scheduled time.
- GitHub notifications depend on user notification settings.
- Branch protection and ruleset settings could not be verified with available access.
- Manual review and CI remain governance controls; direct pushes cannot be prevented by this change.
- Seven-day evidence retention is for this lab, not a compliance archive.

## Acceptance criteria

- Scheduled and manually triggered executions use the same gate and policy.
- Scanner identity, timestamp, run identity, policy verdict, and exit code are recorded.
- HIGH/CRITICAL findings fail the gate; operational errors or invalid results cannot pass.
- Evidence upload is attempted for both passing and failing runs with seven-day retention.
- Existing Windows, Linux, and container checks remain intact.
- Contract tests detect changes to schedule, permissions, retention, policy, and failure handling.
- No new runtime dependencies or externally exposed services are introduced.

## Rollback

Revert the scheduled workflow and related Phase 4 changes through a reviewed pull
request. Preserve the existing security audit workflow and Phase 3 security gates.
