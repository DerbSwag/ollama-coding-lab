import test from 'node:test';
import assert from 'node:assert/strict';
import { runProcess, evaluateImageScan, sbomIdentity } from '../scripts/lib/validation.mjs';

test('ordinary child stderr is captured without converting success to failure', () => {
  const result = runProcess(process.execPath, ['-e', 'console.log("out");console.error("err")']);
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /out/);
  assert.match(result.stderr, /err/);
});
test('child nonzero exit is preserved', () => assert.equal(runProcess(process.execPath, ['-e', 'process.exit(7)']).exitCode, 7));
test('missing executable is a process error, never exit 0', () => {
  const result = runProcess('ollama-lab-nonexistent-executable', []);
  assert.equal(result.exitCode, null);
  assert.equal(result.error, 'ENOENT');
});
test('timed-out child is not successful', () => {
  const result = runProcess(process.execPath, ['-e', 'setTimeout(()=>{},60000)'], { timeout: 100 });
  assert.notEqual(result.exitCode, 0);
  assert.equal(result.error, 'ETIMEDOUT');
});
const clean = { SchemaVersion: 2, Results: [{ Target: 'alpine', Class: 'os-pkgs', Type: 'alpine' }] };
const high = { SchemaVersion: 2, Results: [{ Class: 'os-pkgs', Type: 'alpine', Vulnerabilities: [{ VulnerabilityID: 'SYNTHETIC-001', Severity: 'HIGH' }] }] };
for (const [name, report, code, status] of [
  ['clean success', clean, 0, 'PASS'], ['HIGH blocked', high, 1, 'FAIL'],
  ['finding with exit 0', high, 0, 'BLOCKED'], ['clean with exit 1', clean, 1, 'BLOCKED'],
  ['scanner operational error', clean, 125, 'BLOCKED'], ['missing schema', {}, 0, 'BLOCKED'],
  ['no coverage', { SchemaVersion: 2, Results: [] }, 0, 'BLOCKED'],
  ['missing OS coverage', { SchemaVersion: 2, Results: [{ Target: 'unknown' }] }, 0, 'BLOCKED'],
  ['unknown severity', { SchemaVersion: 2, Results: [{ Class: 'os-pkgs', Type: 'alpine', Vulnerabilities: [{ VulnerabilityID: 'x', Severity: 'SURPRISE' }] }] }, 0, 'BLOCKED'],
  ['null findings', { SchemaVersion: 2, Results: [{ Class: 'os-pkgs', Type: 'alpine', Vulnerabilities: null }] }, 0, 'BLOCKED'],
]) {
  test(`image vulnerability gate: ${name}`, () => assert.equal(evaluateImageScan(report, code).status, status));
}

const configDigest = 'sha256:' + 'a'.repeat(64);
const provenance = { metadata: { component: { properties: [
  { name: 'aquasecurity:trivy:ImageID', value: configDigest },
  { name: 'aquasecurity:trivy:DiffID', value: 'layer-1' },
  { name: 'aquasecurity:trivy:Labels:org.ollama-coding-lab.validation', value: 'synthetic-run' },
] } } };
test('SBOM provenance binds config digest, runtime layers and run identity', () => {
  assert.equal(sbomIdentity(provenance, ['layer-1'], 'synthetic-run').imageConfigDigest, configDigest);
});
test('SBOM with different runtime layers is rejected', () => assert.throws(() => sbomIdentity(provenance, ['different'], 'synthetic-run')));
test('SBOM from a different run is rejected', () => assert.throws(() => sbomIdentity(provenance, ['layer-1'], 'other-run')));
test('SBOM missing provenance is rejected', () => assert.throws(() => sbomIdentity({}, ['layer-1'], 'synthetic-run')));
