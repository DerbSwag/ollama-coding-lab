import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, statSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runProcess, writeJson, sha256, evaluateImageScan, sbomIdentity, scannerUserArgs } from './lib/validation.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const runId = randomUUID();
const output = join(root, '.evidence', `phase3-${runId}`);
mkdirSync(join(output, 'commands'), { recursive: true });
const labelKey = 'org.ollama-coding-lab.validation';
const tag = `ollama-coding-lab:phase3-${runId}`;
const names = { runtime: `ollama-lab-${runId}`, invalid: `ollama-lab-invalid-${runId}` };
const checkNames = ['engine', 'api-tests', 'build', 'image-api-tests', 'runtime-controls',
  'healthcheck-failure', 'startup-failure', 'shutdown-recovery', 'image-export', 'sbom', 'image-vulnerabilities', 'cleanup'];
const report = {
  schemaVersion: 1, runId, startedAtUtc: new Date().toISOString(), status: 'NOT_RUN',
  policy: 'HIGH/CRITICAL image vulnerabilities block; scanner errors and unverifiable controls never pass',
  ollamaUsedForGate: false, imageTag: tag,
  sourceHashes: Object.fromEntries(['Dockerfile', 'package.json', 'server.js', 'healthcheck.js',
    'scripts/validate-container.mjs', 'scripts/lib/validation.mjs', 'tests/api.test.mjs',
    'tests/supply-chain.test.mjs', 'security-tools.json'].map((file) => [file, sha256(join(root, file))])),
  checks: Object.fromEntries(checkNames.map((name) => [name, { status: 'NOT_RUN' }])),
};
let sequence = 0;
let imageId;
let archiveHash;
const save = () => writeJson(join(output, 'phase3.json'), report);
save();
const block = (message) => Object.assign(new Error(message), { blocked: true });
function command(commandName, args, timeout = 120_000) {
  const result = runProcess(commandName, args, { cwd: root, timeout });
  writeJson(join(output, 'commands', `${String(++sequence).padStart(3, '0')}.json`), { command: commandName, args, ...result });
  return result;
}
function requireSuccess(result, message) {
  if (result.error) throw block(`${message}: ${result.error}`);
  assert.equal(result.exitCode, 0, `${message}: exit ${result.exitCode}`);
  return result.stdout.trim();
}
const docker = (args, timeout) => command('docker', args, timeout);
const inspect = (name) => JSON.parse(requireSuccess(docker(['inspect', name]), 'Inspect container'))[0];
async function step(name, action) {
  try { report.checks[name] = { status: 'PASS', details: await action() }; }
  catch (error) {
    report.checks[name] = { status: error.blocked ? 'BLOCKED' : 'FAIL', message: error.message };
  }
  console.log(`${name}: ${report.checks[name].status}`);
  save();
}
const passed = (name) => report.checks[name].status === 'PASS';
function containerArgs(name) {
  return ['run', '--detach', '--name', name, '--label', `${labelKey}=${runId}`,
    '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit', '64', '--memory', '128m'];
}
async function healthy(name) {
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline) {
    const data = inspect(name);
    if (!data.State.Running) throw new Error('Container exited before health validation');
    if (data.State.Health?.Status === 'healthy') return data;
    await new Promise((resolveWait) => setTimeout(resolveWait, 500));
  }
  throw new Error('Container did not become healthy within 45 seconds');
}
async function httpHealth(data) {
  const bindings = data.NetworkSettings.Ports['3000/tcp'];
  assert.ok(bindings?.length > 0, 'Published port missing');
  assert.ok(bindings.every((binding) => binding.HostIp === '127.0.0.1'), 'Port must bind only localhost');
  const response = await fetch(`http://127.0.0.1:${bindings[0].HostPort}/health`, { signal: AbortSignal.timeout(5_000) });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: 'ok' });
  return bindings;
}
function removeOwned(name) {
  const list = docker(['ps', '--all', '--filter', `name=^/${name}$`, '--format', '{{.Names}}']);
  const found = requireSuccess(list, 'List owned container');
  if (!found) return;
  assert.equal(found, name, 'Unexpected cleanup target');
  assert.equal(inspect(name).Config.Labels[labelKey], runId, 'Refusing cleanup of unowned container');
  requireSuccess(docker(['rm', '--force', name]), 'Remove owned container');
  assert.equal(requireSuccess(docker(['ps', '--all', '--filter', `name=^/${name}$`, '--format', '{{.Names}}']), 'Verify cleanup'), '');
}

try {
  await step('engine', () => {
    const result = docker(['info', '--format', '{"ServerVersion":"{{.ServerVersion}}","OSType":"{{.OSType}}","Architecture":"{{.Architecture}}"}']);
    if (result.error || result.exitCode !== 0) throw block('Docker Engine unavailable');
    const data = JSON.parse(result.stdout);
    assert.equal(data.OSType, 'linux');
    return { version: data.ServerVersion, osType: data.OSType, architecture: data.Architecture };
  });
  await step('api-tests', () => {
    const result = command(process.execPath, ['--test', '--test-reporter=tap', 'tests/api.test.mjs', 'tests/supply-chain.test.mjs']);
    requireSuccess(result, 'API and runner/policy tests');
    assert.match(result.stdout, /# fail 0\b/);
    assert.match(result.stdout, /# cancelled 0\b/);
    const tests = Number(result.stdout.match(/# tests (\d+)/)?.[1]);
    assert.ok(Number.isInteger(tests) && tests > 0, 'No executed test assertions reported');
    return { tests, skipped: Number(result.stdout.match(/# skipped (\d+)/)?.[1]), exitCode: result.exitCode };
  });
  if (passed('engine') && passed('api-tests')) {
    await step('build', () => {
      requireSuccess(docker(['build', '--pull', '--platform', 'linux/amd64', '--label', `${labelKey}=${runId}`,
        '--tag', tag, '--iidfile', join(output, 'image.id'), '.'], 600_000), 'Image build');
      imageId = readFileSync(join(output, 'image.id'), 'utf8').trim();
      assert.match(imageId, /^sha256:[a-f0-9]{64}$/);
      const data = JSON.parse(requireSuccess(docker(['image', 'inspect', imageId]), 'Image identity'))[0];
      assert.equal(data.Config.Labels[labelKey], runId);
      report.imageId = imageId;
      report.imageLayers = data.RootFS.Layers;
      return { imageId, tag, user: data.Config.User, platform: `${data.Os}/${data.Architecture}` };
    });
  }
  if (passed('build')) {
    await step('image-api-tests', () => {
      const result = docker(['run', '--rm', '--name', `${names.runtime}-tests`, '--label', `${labelKey}=${runId}`,
        '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--network=none',
        '--mount', `type=bind,source=${join(root, 'tests')},target=/app/tests,readonly`,
        imageId, 'node', '--test', '--test-reporter=tap', '/app/tests/api.test.mjs']);
      requireSuccess(result, 'API tests against image source');
      assert.match(result.stdout, /# fail 0\b/);
      assert.match(result.stdout, /# skipped 0\b/);
      const tests = Number(result.stdout.match(/# tests (\d+)/)?.[1]);
      assert.ok(Number.isInteger(tests) && tests > 0);
      return { exitCode: result.exitCode, tests, signalsVerified: ['SIGTERM', 'SIGINT'] };
    });
    await step('runtime-controls', async () => {
      requireSuccess(docker([...containerArgs(names.runtime), '--publish', '127.0.0.1::3000', imageId]), 'Start hardened container');
      const data = await healthy(names.runtime);
      assert.equal(data.Image, imageId);
      assert.equal(data.HostConfig.ReadonlyRootfs, true);
      assert.ok(data.HostConfig.CapDrop.includes('ALL'));
      assert.ok(data.HostConfig.SecurityOpt.includes('no-new-privileges'));
      const probe = JSON.parse(requireSuccess(docker(['exec', names.runtime, 'node', '-e',
        `const fs=require('node:fs');const s=fs.readFileSync('/proc/1/status','utf8');let writeError;try{fs.writeFileSync('/tmp/ollama-lab-probe','x')}catch(e){writeError=e.code}console.log(JSON.stringify({nodeVersion:process.versions.node,uid:process.getuid(),pid1:s.match(/^Uid:\\s+(\\d+)/m)[1],caps:s.match(/^CapEff:\\s+(\\w+)/m)[1],bounding:s.match(/^CapBnd:\\s+(\\w+)/m)[1],noNewPrivs:s.match(/^NoNewPrivs:\\s+(\\d+)/m)[1],writeError}))`]), 'Kernel controls probe'));
      assert.notEqual(probe.uid, 0);
      assert.notEqual(probe.pid1, '0');
      assert.match(probe.caps, /^0+$/);
      assert.match(probe.bounding, /^0+$/);
      assert.equal(probe.noNewPrivs, '1');
      assert.equal(probe.writeError, 'EROFS');
      const bindings = await httpHealth(data);
      return { ...probe, readonlyRootfs: true, capDrop: data.HostConfig.CapDrop,
        securityOpt: data.HostConfig.SecurityOpt, bindings, containerHealth: data.State.Health.Status, httpHealth: { status: 'ok' } };
    });
    await step('startup-failure', () => {
      requireSuccess(docker([...containerArgs(names.invalid), '--network=none', '--env', 'PORT=invalid', imageId]), 'Start intentionally invalid container');
      assert.equal(requireSuccess(docker(['wait', names.invalid], 15_000), 'Wait for startup failure'), '1');
      const data = inspect(names.invalid);
      assert.equal(data.State.ExitCode, 1);
      assert.equal(data.State.Running, false);
      // Node writes configuration failures to stderr, captured separately.
      const logResult = docker(['logs', names.invalid]);
      requireSuccess(logResult, 'Startup failure log capture');
      assert.match(logResult.stdout + logResult.stderr, /invalid_configuration/);
      removeOwned(names.invalid);
      return { expectedExitCode: 1, observedExitCode: data.State.ExitCode, cleanupVerified: true };
    });
    await step('healthcheck-failure', () => {
      const result = docker(['run', '--rm', '--name', `${names.runtime}-health-failure`, '--label', `${labelKey}=${runId}`,
        '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--network=none', imageId, 'node', 'healthcheck.js']);
      if (result.error) throw block('Health failure probe could not run');
      assert.equal(result.exitCode, 1, 'Healthcheck must reject an absent HTTP service');
      return { expectedExitCode: 1, observedExitCode: result.exitCode };
    });
    if (passed('runtime-controls')) {
      await step('shutdown-recovery', async () => {
        requireSuccess(docker(['stop', '--time', '10', names.runtime]), 'Graceful container stop');
        assert.equal(inspect(names.runtime).State.ExitCode, 0);
        assert.match(requireSuccess(docker(['logs', names.runtime]), 'Shutdown logs'), /shutdown/);
        requireSuccess(docker(['start', names.runtime]), 'Restart owned container');
        await httpHealth(await healthy(names.runtime));
        return { sigtermExitCode: 0, recovered: true };
      });
    }
    await step('image-export', () => {
      const archive = join(output, 'image.tar');
      requireSuccess(docker(['image', 'save', '--output', archive, imageId], 120_000), 'Export exact image');
      archiveHash = sha256(archive);
      report.archiveSha256 = archiveHash;
      return { imageId, sha256: archiveHash };
    });
    if (passed('image-export')) {
      const tools = JSON.parse(readFileSync(join(root, 'security-tools.json'), 'utf8').replace(/^\uFEFF/, ''));
      assert.match(tools.trivy, /@sha256:[a-f0-9]{64}$/);
      report.scanner = tools.trivy;
      const cacheDir = join(output, 'cache');
      mkdirSync(cacheDir, { recursive: true });
      const scannerUser = scannerUserArgs(process.platform, statSync(cacheDir));
      const scanner = ['run', '--rm', '--name', `${names.runtime}-scanner`, '--label', `${labelKey}=${runId}`, '--read-only', '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,nodev', ...scannerUser,
        '--mount', `type=bind,source=${join(output, 'image.tar')},target=/input/image.tar,readonly`,
        '--mount', `type=bind,source=${cacheDir},target=/cache`, tools.trivy,
        '--cache-dir', '/cache', '--config', '/dev/null', 'image', '--input', '/input/image.tar',
        '--scanners', 'vuln', '--ignorefile', '/dev/null', '--skip-version-check', '--timeout', '10m'];
      await step('sbom', () => {
        const result = docker([...scanner, '--format', 'cyclonedx', '--exit-code', '0'], 660_000);
        if (result.error || result.exitCode !== 0) throw block('SBOM scanner unavailable or failed operationally');
        const sbom = JSON.parse(requireSuccess(result, 'CycloneDX generation'));
        assert.equal(sbom.bomFormat, 'CycloneDX');
        assert.ok(sbom.specVersion && sbom.serialNumber && sbom.components?.length > 0);
        writeJson(join(output, 'sbom.cdx.json'), sbom);
        try { report.provenance = sbomIdentity(sbom, report.imageLayers, runId); }
        catch { throw block('SBOM/runtime image provenance could not be verified'); }
        assert.equal(sha256(join(output, 'image.tar')), archiveHash);
        return { format: sbom.bomFormat, specVersion: sbom.specVersion, components: sbom.components.length, sha256: sha256(join(output, 'sbom.cdx.json')) };
      });
      await step('image-vulnerabilities', () => {
        const result = docker([...scanner, '--format', 'json', '--severity', 'HIGH,CRITICAL', '--exit-code', '1'], 660_000);
        if (result.error || ![0, 1].includes(result.exitCode)) throw block('Image scanner unavailable or failed operationally');
        let parsed;
        try { parsed = JSON.parse(result.stdout); }
        catch { throw block('Image scanner returned invalid JSON'); }
        writeJson(join(output, 'image-vulnerabilities.json'), parsed);
        try {
          assert.deepEqual(parsed.Metadata.DiffIDs, report.imageLayers);
          assert.equal(parsed.Metadata.ImageID, report.provenance.imageConfigDigest);
          assert.equal(parsed.Metadata.ImageConfig.config.Labels[labelKey], runId);
        } catch { throw block('Image vulnerability report/runtime provenance could not be verified'); }
        const verdict = evaluateImageScan(parsed, result.exitCode);
        report.imageScan = { ...verdict, exitCode: result.exitCode };
        if (verdict.status === 'BLOCKED') throw block(verdict.reason);
        assert.equal(verdict.status, 'PASS', 'Blocking HIGH/CRITICAL image vulnerabilities found');
        if (!parsed.Results.some((item) => item.Class === 'os-pkgs')) throw block('OS package scan coverage missing');
        assert.equal(sha256(join(output, 'image.tar')), archiveHash);
        return { ...verdict, exitCode: result.exitCode, sha256: sha256(join(output, 'image-vulnerabilities.json')) };
      });
    }
  }
} catch (error) {
  report.orchestratorError = error.message;
} finally {
  if (passed('engine')) {
    await step('cleanup', () => {
      const errors = [];
      for (const name of [names.runtime, names.invalid, `${names.runtime}-tests`, `${names.runtime}-scanner`, `${names.runtime}-health-failure`]) {
        try { removeOwned(name); } catch (error) { errors.push(error.message); }
      }
      assert.equal(errors.length, 0, `Owned container cleanup incomplete: ${errors.join('; ')}`);
      return { ownedContainersRemoved: true, imageRetained: tag, noUnrelatedResourcesTouched: true };
    });
  }
  const statuses = Object.values(report.checks).map((check) => check.status);
  report.status = !report.orchestratorError && statuses.every((status) => status === 'PASS') ? 'PASS'
    : statuses.includes('FAIL') ? 'FAIL' : 'BLOCKED';
  report.finishedAtUtc = new Date().toISOString();
  report.exitCode = report.status === 'PASS' ? 0 : 1;
  save();
  console.log(`Phase 3: ${report.status}. Evidence: ${output}`);
  process.exitCode = report.exitCode;
}
