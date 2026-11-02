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
