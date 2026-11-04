import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import assert from 'node:assert/strict';

export function runProcess(command, args, { timeout = 120_000, cwd } = {}) {
  const started = Date.now();
  const result = spawnSync(command, args, { encoding: 'utf8', timeout, cwd, maxBuffer: 64 * 1024 * 1024, windowsHide: true });
  return {
    exitCode: result.status, signal: result.signal, error: result.error?.code ?? null,
    stdout: result.stdout ?? '', stderr: result.stderr ?? '', durationMs: Date.now() - started,
  };
}
export function writeJson(path, value) { writeFileSync(path, JSON.stringify(value, null, 2) + '\n'); }
export function sha256(path) { return createHash('sha256').update(readFileSync(path)).digest('hex'); }

export function sbomIdentity(sbom, runtimeLayers, runId) {
  const properties = sbom.metadata?.component?.properties;
  assert.ok(Array.isArray(properties), 'SBOM image provenance missing');
  const values = (name) => properties.filter((item) => item.name === name).map((item) => item.value);
  const ids = values('aquasecurity:trivy:ImageID');
  assert.equal(ids.length, 1);
  assert.match(ids[0], /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(values('aquasecurity:trivy:DiffID').sort(), [...runtimeLayers].sort(), 'SBOM/runtime layers differ');
  assert.deepEqual(values('aquasecurity:trivy:Labels:org.ollama-coding-lab.validation'), [runId], 'SBOM run identity differs');
  return { imageConfigDigest: ids[0], layerDiffIds: [...runtimeLayers] };
}

export function evaluateImageScan(report, exitCode) {
  if (report?.SchemaVersion !== 2 || !Array.isArray(report.Results) || report.Results.length === 0) {
    return { status: 'BLOCKED', reason: 'invalid-or-empty-report', blockingFindings: null };
  }
  if (!report.Results.some((item) => item?.Class === 'os-pkgs' && typeof item.Type === 'string')) {
    return { status: 'BLOCKED', reason: 'missing-os-coverage', blockingFindings: null };
  }
  let count = 0;
  for (const result of report.Results) {
    if (!result || typeof result !== 'object' || Array.isArray(result)) return { status: 'BLOCKED', reason: 'invalid-result', blockingFindings: null };
    if (!Object.hasOwn(result, 'Vulnerabilities')) continue;
    if (!Array.isArray(result.Vulnerabilities)) return { status: 'BLOCKED', reason: 'invalid-findings', blockingFindings: null };
    for (const finding of result.Vulnerabilities) {
      if (!finding || typeof finding.VulnerabilityID !== 'string' || !finding.VulnerabilityID ||
          !['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(finding.Severity)) {
        return { status: 'BLOCKED', reason: 'invalid-finding', blockingFindings: null };
      }
      if (['HIGH', 'CRITICAL'].includes(finding.Severity)) count++;
    }
  }
  if (![0, 1].includes(exitCode)) return { status: 'BLOCKED', reason: 'scanner-error', blockingFindings: count };
  if ((count > 0) !== (exitCode === 1)) return { status: 'BLOCKED', reason: 'json-exit-code-mismatch', blockingFindings: count };
  return { status: count ? 'FAIL' : 'PASS', reason: 'consistent', blockingFindings: count };
}
