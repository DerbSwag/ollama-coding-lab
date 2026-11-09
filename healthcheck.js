import { get } from 'node:http';

const maxBodyBytes = 1024;
const probeDeadlineMs = 2_500;
process.exitCode = 1;
let failed = false;
let completed = false;
let body = '';
let request;
const deadline = setTimeout(() => fail(), probeDeadlineMs);
deadline.unref();
const fail = () => {
  if (failed) return;
  failed = true;
  process.exitCode = 1;
  clearTimeout(deadline);
  request?.destroy();
};
request = get({ host: '127.0.0.1', port: Number(process.env.PORT ?? 3000), path: '/health', timeout: 2_000 }, (incoming) => {
  incoming.setEncoding('utf8');
  incoming.on('data', (chunk) => {
    if (failed) return;
    body += chunk;
    if (Buffer.byteLength(body, 'utf8') > maxBodyBytes) fail();
  });
  incoming.on('aborted', fail);
  incoming.on('error', fail);
  incoming.on('close', () => { if (!completed) fail(); });
  incoming.on('end', () => {
    if (failed || incoming.complete !== true) return fail();
    completed = true;
    try {
      const value = JSON.parse(body);
      if (incoming.statusCode === 200 && value?.status === 'ok') {
        clearTimeout(deadline);
        process.exitCode = 0;
      } else {
        fail();
      }
    } catch {
      fail();
    }
  });
});
request.on('timeout', fail);
request.on('error', fail);
