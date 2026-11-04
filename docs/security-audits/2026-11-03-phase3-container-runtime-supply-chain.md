# Phase 3: container runtime validation and supply chain

## Scope and authorization

Branch: `feature/container-runtime-supply-chain`.
Verified starting tree: clean; HEAD/main baseline
`6677200ac8f92205422bef928f066ac148984ac9`. Actor: Codex local assistant.
The user explicitly selected a built-in-module-only demo API and authorized local
Docker validation. No commit, push, PR, merge or deployment is authorized/performed.

## Remediation Implemented

- Add dependency-free `server.js` and `package.json`: GET service/health JSON,
  404/405 semantics, malformed-URL rejection, bounded SIGTERM/SIGINT shutdown and
  explicit nonzero invalid-config/startup handling. No external npm installation.
- Pin the official Node 24 Alpine image to
  `sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85`.
  Registry manifest inspection and execution verified Node 24.22.2. The initially
  guessed 24.14.0-alpine3.24 tag did not exist; no guessed tag was used in a build.
- Replace npm install/full-repo COPY with an explicit three-file COPY, non-root
  node user and real Node HTTP HEALTHCHECK. Remove unused npm/Yarn/Corepack in a
  preparation stage and copy the cleaned filesystem into the final scratch stage,
  eliminating removed package bytes from final layers. Alpine libraries remain.
- Add node:test/node:assert API tests and native process/image-policy/provenance
  regression tests: stderr success, nonzero/timeout/missing executable, malformed
  report, empty OS coverage, JSON/exit mismatch and foreign SBOM/run/layer rejection.
- Add `validate-container.mjs` with per-check JSON, explicit NOT_RUN prerequisites,
  fail-closed status/exit handling, unique owned image/container names and guarded
  cleanup. Verify build, actual UID/capabilities/NNP/EROFS, loopback port, healthy
  container/HTTP, invalid startup, absent-service healthcheck, shutdown and recovery.
- Generate CycloneDX SBOM and scan an immutable exported image with the original
  digest-pinned Trivy. Mount archive read-only plus a dedicated writable cache;
  never mount a host Docker socket. HIGH/CRITICAL findings block, errors are BLOCKED.
- Bind source hashes, runtime Docker identity, rootfs DiffIDs, unique owner label,
  archive SHA256, SBOM configuration digest and vulnerability report together.
  Docker OCI index and Trivy configuration digest are recorded separately, with
  layer/run-identity verification instead of incorrectly requiring those IDs equal.
- Add a separate CI job requiring the original static gate, preserve the original
  jobs/gate scripts/tool pins/negative fixture, add this feature branch trigger and
  upload explicit JSON/SBOM allowlists. No artifact archive/cache upload or privilege
  expansion. Extend collector hash allowlist; add README/runbook/incident records.

## Confirmed vulnerability remediation

First run `.evidence/phase3-7328cd3e-995e-4a18-bb73-8b1926fb5507/` built and ran
successfully but was correctly rejected with 6 HIGH findings and exit 1. All paths
were under `usr/local/lib/node_modules/npm/node_modules/`, not demo dependencies.

| Finding | Package in original base runtime | Resolution in final runtime |
| --- | --- | --- |
| CVE-2026-102276 | brace-expansion 5.0.9 | Remove unused bundled npm dependency tree |
| CVE-2026-102278 | brace-expansion 5.0.9 | Remove unused bundled npm dependency tree |
| CVE-2026-109383 | undici 6.28.0 | Remove unused bundled npm dependency tree |
| CVE-2026-109869 | undici 6.28.0 | Remove unused bundled npm dependency tree |
| CVE-2026-19534 | undici 6.28.0 | Remove unused bundled npm dependency tree |
| CVE-2026-87018 | undici 6.28.0 | Remove unused bundled npm dependency tree |

No severity reduction, scanner suppression, VEX/ignore exemption or LLM override
was introduced. The final image was rescanned: 0 HIGH/CRITICAL blockers. This means
no matching blockers in the scanner's present coverage/database, not no possible CVEs.

## Final verified local results

Final run: `.evidence/phase3-e5c361ec-91e3-4cbb-9133-cefa3e8f8603/`.
Overall PASS, exit 0, 12/12 required checks PASS. Tested on Windows PowerShell 5.1,
host Node 24.14.0, Docker Desktop Engine 29.9.2, Linux/amd64 image Node 24.22.2.

| Check | Observed result |
| --- | --- |
| Host API/process/policy/provenance tests | 32 total, 30 pass, 2 Windows signal cases skipped, 0 fail |
| Built-image API tests | 14/14 pass, no skips; SIGTERM and SIGINT both exit 0 |
| Image build | PASS; dependency-free build, no npm install |
| Effective user | UID 1000, PID 1 UID 1000 |
| Capabilities | Effective and bounding masks both 0000000000000000; CapDrop ALL |
| No-new-privileges | Kernel NoNewPrivs 1 and matching inspect option |
| Read-only root | Inspect true, write probe returns EROFS |
| Health and port | Container healthy; HTTP 200 with status ok; only 127.0.0.1 port binding |
| Negative startup / health probe | Both observed exit 1; failed startup container cleanup verified |
| Shutdown/recovery | SIGTERM container stop exit 0; same owned container restarted and healthy |
| SBOM | CycloneDX 1.7, 21 components, provenance checks pass |
| Image vulnerability gate | PASS, exit 0, 0 HIGH/CRITICAL blockers, consistent JSON/exit |
| Cleanup | Exact owned containers removed; image retained; no unrelated resource modification |

Identity chain recorded in phase3.json:

- Runtime Docker OCI image identity:
  `sha256:47c2d24005887300d9c24cbaf09f63af659c64650183e047fc0948fed443834d`.
- Export SHA256: `6357f534e28ca8280d932a3aa07f6bd28e4687b992fc6bade1ac99a8d3ae6e46`.
- Image configuration digest reported by SBOM/Trivy:
  `sha256:ba2245820416c8812dcc93d4dc07626ffee9c9acb7f72a858b1723e8eb3fd2c3`.
- SBOM SHA256: `c1f09d682c6964ff537af02cca9a445d2f0e206a2f06d3d56fec5fe097fdda20`.
- Vulnerability report SHA256: `df25ff40d1b606a13f67b105c8d19f0c9cfe9ed80ad544a3f6099353d9efa235`.

Final source-hash comparison passed. Command exit codes, stdout, stderr and durations
are preserved under `commands/`. Reports are ignored locally, not committed.
The final JSON explicitly records `exitCode: 0`; the blocked simulation records 1.

## Existing gate preservation and failure evidence

- Original contract tests PASS 37/37 on Windows PowerShell 5.1:
  `.evidence/phase3-original-contracts-ps51.log`,
  `.evidence/gate-test-09098fd7215b41d29de421721f00eb84/test-results.json`.
- Original contracts PASS 37/37 on PowerShell 7.5/Linux:
  `.evidence/phase3-original-contracts-ps7.log`,
  `.evidence/gate-test-ff15beb66169476f9627b42f80294791/test-results.json`.
- Final Dockerfile original scanner integration PASS 2/2, exit 0:
  `.evidence/scanner-integration-dab4afa0d6f245f7bf74ca8993e73c8c/test-results.json`
  and `.evidence/phase3-final-static-integration.log`. Secure root passes; original
  insecure fixture is still rejected for HIGH DS-0002. Root gate.json records PASS.
- actionlint 1.7.7 PASS, exit 0: `.evidence/phase3-actionlint.json`.
- Original contract/static workflow jobs are semantically identical to baseline;
  original gate/tests/tool pins/negative fixture have no diff. Evidence:
  `.evidence/phase3-preservation.json`.
- Unavailable-Docker simulation with final source returned overall BLOCKED/exit 1;
  build/runtime/SBOM/scan checks remain NOT_RUN. Only the child-session PATH was
  temporarily changed/restored; the real daemon remained running. Evidence:
  `.evidence/phase3-210fecd3-b6c8-407f-8f36-7a04509d0686/phase3.json`.

## Commands, limitations and remaining gates

See RUNBOOK.md for exact runnable commands and failure/cleanup/rollback procedures.
Main command: `node scripts/validate-container.mjs`; JavaScript tests:
`node --test tests/api.test.mjs tests/supply-chain.test.mjs`. Original PowerShell
contract/integration commands remain unchanged.

Phase 3 GitHub-hosted execution/artifact upload is NOT_RUN: publishing is forbidden
in the current authorization. Hosted compatibility is a pending acceptance gate,
not inferred from local success. No commit/push/PR/merge/deploy performed.

Only Linux/amd64 was run. Windows signal tests are skipped locally and verified
inside Linux instead. SBOM checks validate core fields/identity, not every official
schema constraint. Digest pinning is immutable input selection, not publisher
signature verification; provenance is unsigned. Build UUID labels/timestamps make
outputs identifiable but not byte-identical across runs. Scan coverage/database
changes can introduce new findings. No production auth/TLS/load/data durability
claims, OS sandbox guarantee, or full supply-chain security certification is made.

## Rollback and retained resources

Main remains unchanged at the baseline. Source is uncommitted and preserved for
review; no reset/checkout/clean/revert performed. No service was deployed. Owned
container stop/start recovery and failed-start cleanup were verified. Uniquely
tagged local images, archives and caches remain for inspection; unrelated resources
were never deleted. For manual rollback/cleanup, use exact recorded IDs and labels
as described in RUNBOOK.md, with authorization for any source restoration.
