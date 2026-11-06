import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { get } from 'node:http';
import { fileURLToPath } from 'node:url';
import { createApp } from '../server.js';
import { createServer } from 'node:http';

const healthcheck = fileURLToPath(new URL('../healthcheck.js', import.meta.url));

async function runHealthcheck(t, handler) {
  const server = createServer(handler).listen(0, '127.0.0.1');
  await once(server, 'listening');
  let child;
  t.after(async () => {
    if (child && child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
      await Promise.race([once(child, 'exit'), new Promise((resolve) => setTimeout(resolve, 1_000))]);
    }
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  child = spawn(process.execPath, [healthcheck], {
    env: { ...process.env, PORT: String(server.address().port) }, stdio: 'ignore',
  });
  const exit = await Promise.race([
    once(child, 'exit').then(([code]) => ({ code })),
    once(child, 'error').then((error) => ({ error })),
    new Promise((resolve) => setTimeout(() => resolve({ timeout: true }), 5_000)),
  ]);
  if (exit.error) throw new Error(`Unable to spawn healthcheck: ${exit.error.message}`);
  if (exit.timeout) throw new Error('Healthcheck child exceeded 5 second test deadline');
  const code = exit.code;
  return code;
}

test('healthcheck accepts a complete healthy response', async (t) => {
  assert.equal(await runHealthcheck(t, (_req, res) => res.end('{"status":"ok"}')), 0);
});
test('healthcheck rejects HTTP error responses', async (t) => {
  assert.equal(await runHealthcheck(t, (_req, res) => { res.statusCode = 503; res.end('{"status":"ok"}'); }), 1);
});
test('healthcheck rejects malformed JSON', async (t) => {
  assert.equal(await runHealthcheck(t, (_req, res) => res.end('{')), 1);
});
test('healthcheck rejects oversized bodies', async (t) => {
  assert.equal(await runHealthcheck(t, (_req, res) => res.end('x'.repeat(1025))), 1);
});
test('healthcheck rejects prematurely closed responses', async (t) => {
  assert.equal(await runHealthcheck(t, (_req, res) => { res.writeHead(200, { 'Content-Length': '100' }); res.write('{'); res.destroy(); }), 1);
});
test('healthcheck rejects a partial HTTP 200 response that times out', { timeout: 10_000 }, async (t) => {
  assert.equal(await runHealthcheck(t, (_req, res) => { res.writeHead(200); res.write('{'); }), 1);
});
test('healthcheck rejects connection refusal', async (t) => {
  const server = createServer().listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  const child = spawn(process.execPath, [healthcheck], { env: { ...process.env, PORT: String(port) }, stdio: 'ignore' });
  const [code] = await once(child, 'exit');
  assert.equal(code, 1);
});

test('HTTP routing and method contract', async (t) => {
  const server = createApp().listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  await t.test('GET / gives service information', async () => {
    const result = await fetch(base);
    assert.equal(result.status, 200);
    assert.deepEqual(await result.json(), { service: 'ollama-coding-lab-demo', version: '1.0.0' });
  });
  await t.test('GET /health gives exact healthy body', async () => {
    const result = await fetch(`${base}/health`);
    assert.equal(result.status, 200);
    assert.deepEqual(await result.json(), { status: 'ok' });
    assert.match(result.headers.get('content-type'), /application\/json/);
  });
  await t.test('unknown route is 404', async () => {
    const result = await fetch(`${base}/unknown`);
    assert.equal(result.status, 404);
    assert.deepEqual(await result.json(), { error: 'not_found' });
  });
  await t.test('malformed URL is 400 and does not crash the server', async () => {
    const status = await new Promise((resolve, reject) => {
      get({ host: '127.0.0.1', port: server.address().port, path: 'http://[' }, (response) => {
        response.resume();
        response.on('end', () => resolve(response.statusCode));
      }).on('error', reject);
    });
    assert.equal(status, 400);
    assert.equal((await fetch(`${base}/health`)).status, 200);
  });
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']) {
    await t.test(`${method} is rejected with 405 and Allow`, async () => {
      const result = await fetch(`${base}/health`, { method });
      assert.equal(result.status, 405);
      assert.equal(result.headers.get('allow'), 'GET');
    });
  }
});

const script = fileURLToPath(new URL('../server.js', import.meta.url));
test('invalid configuration exits nonzero', { timeout: 10_000 }, async () => {
  const child = spawn(process.execPath, [script], { env: { ...process.env, PORT: 'invalid' }, stdio: 'pipe' });
  const [code] = await once(child, 'exit');
  assert.equal(code, 1);
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  test(`graceful ${signal} closes child with exit 0`, { skip: process.platform === 'win32', timeout: 10_000 }, async (t) => {
    const child = spawn(process.execPath, [script], { env: { ...process.env, PORT: '0' }, stdio: ['ignore', 'pipe', 'pipe'] });
    t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
    let output = '';
    await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('exit', () => reject(new Error('Child exited before listening')));
      child.stdout.on('data', (data) => { output += data; if (output.includes('listening')) resolve(); });
    });
    const exited = once(child, 'exit');
    child.kill(signal);
    const [code, exitSignal] = await exited;
    assert.equal(code, 0);
    assert.equal(exitSignal, null);
    assert.match(output, /shutdown/);
  });
}
