# PR #1 final review and Action runtime refresh

## Scope and verified remote baseline

Read-only GitHub inspection on 2026-11-03 confirmed
[PR #1](https://github.com/DerbSwag/ollama-coding-lab/pull/1) is open, not draft,
mergeable and not merged, with head `0b2e1d458c195b405cd3107eccfd679c94a70870`,
base `main`, 3 commits and 14 changed files. These are baseline observations,
not results for the new Action references.

- Push run [41652666299](https://github.com/DerbSwag/ollama-coding-lab/actions/runs/41652666299):
  Ubuntu contracts, Windows contracts and static gate all concluded success.
- PR run [41653749463](https://github.com/DerbSwag/ollama-coding-lab/actions/runs/41653749463):
  all three jobs and artifact upload steps concluded success. Artifact IDs:
  13238392549 (Ubuntu), 13238686905 (Windows), 13239375098 (static evidence).
- [Codex summary comment](https://github.com/DerbSwag/ollama-coding-lab/pull/1#issuecomment-6606401716)
  reports code review completed for `0b2e1d4`, no findings and no unresolved
  findings. Formal review submissions and inline review threads were empty.
  No separate Codex security review completion is claimed.

## Final review observations

Inspected the workflow, gate/collector scripts, contract/integration tests,
Dockerfile, build/scan exclusions and tool pins against main. No additional
blocking defect was identified in this scoped manual review. This is not an
exhaustive security certification.

- Token permission is `contents: read`; credential persistence is disabled.
- No `pull_request_target`, unsafe context interpolation in run blocks, secret
  access, deployment step, LLM override, or `continue-on-error` is introduced.
- All Actions have full SHA pins, scanners retain digest pins, containers mount
  source read-only, and HIGH/CRITICAL policy/JSON-exit consistency remain enforced.
- Contracts are required before policy acceptance; positive and negative fixtures
  are separate. Fixture exclusions and their isolated scans are explicitly documented.
- Application build/runtime remains out of scope: no package manifest or server
  implementation exists. Required-check/branch protection settings were not audited
  or changed. Merge remains a human decision after fresh checks.

## Confirmed cause of runtime warning

The pinned checkout v4.3.1 and upload-artifact v4.6.2 both declare
`runs.using: node20` in their official SHA-addressed action.yml files. The Node.js
20 deprecation warning reported in the PR is consistent with those declarations;
this is runtime maintenance, not evidence of an exploited vulnerability.

## Remediation Implemented

Update only four workflow Action references, retaining immutable SHA pinning:

| Action | Previous reference | New reference |
| --- | --- | --- |
| checkout (2 uses) | v4.3.1 / `34e114876b0b11c390a56381ad16ebd13914f8d5` | v7.0.1 / `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| upload-artifact (2 uses) | v4.6.2 / `ea165f8d65b6e75b540449e92b4886f43607fa02` | v7.0.2 / `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |

Both new releases declare `runs.using: node24`. Official release tag SHAs were
resolved with `git ls-remote`; metadata was downloaded by those exact SHAs.
Configured inputs remain supported, including hidden-file upload and 7-day
retention. Upload v7 defaults to ZIP archiving, preserving multi-file artifacts.
Checkout v7's unsafe-PR opt-in remains at its safe default; this workflow uses
ordinary pull_request triggers. Policy, runner matrix, guard, paths, permissions,
timeouts and all script/scanner code are unchanged.

Official sources:
[checkout action metadata](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/action.yml),
[upload action metadata](https://github.com/actions/upload-artifact/blob/cf430e030ddbb5b0abf93d22962f4752f3646cd9/action.yml),
[checkout compatibility notes](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/README.md).
Node24 Actions require a compatible runner (checkout documents minimum 2.327.1).
The workflow targets GitHub-hosted runners; self-hosted compatibility is not tested.

## Validation and evidence

- PASS: exact-SHA metadata confirms old runtimes node20 and new runtimes node24.
- PASS: YAML comparison confirms only the four Action references changed;
  every configured input is supported and artifact archive default remains true.
  Evidence: `.evidence/actions-node24/compatibility.json` and the four downloaded
  old/new action.yml files in that directory.
- PASS: actionlint 1.7.7 on Windows, exit 0. Release ZIP checksum verified against
  official release checksums before executing the standalone binary. Evidence:
  `.evidence/actions-node24/actionlint-result.json`.
- Docker-based actionlint attempt: BLOCKED because Docker Desktop's named pipe
  was unavailable. The native validator above completed instead; no daemon started.
- Cross-platform contracts and real scanner integration: not rerun locally for
  this references-only change. The verified baseline runs above cover the unchanged
  scripts; they do not validate the new Actions' runtime execution or uploads.
- New head GitHub-hosted checks, artifact uploads and disappearance of runtime
  warnings: NOT_RUN, pending an explicitly approved push. No push, PR comment,
  PR metadata edit, merge or branch-protection change performed in this session.

## Rollback and merge gate

Revert the separate runtime-refresh commit after review to restore the previous
four pins (and their Node20 warning). No rollback executed. After approved push,
check all three jobs and artifacts at the new head, confirm no Node20 runtime
warnings, refresh review if needed, then decide whether to squash-merge PR #1.
