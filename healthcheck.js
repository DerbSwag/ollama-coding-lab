import { get } from 'node:http';

const request = get({ host: '127.0.0.1', port: Number(process.env.PORT ?? 3000), path: '/health', timeout: 2_000 }, (response) => {
  let body = '';
  response.setEncoding('utf8');
  response.on('data', (chunk) => { body += chunk; if (body.length > 1024) request.destroy(); });
  response.on('end', () => {
    try { process.exitCode = response.statusCode === 200 && JSON.parse(body).status === 'ok' ? 0 : 1; }
    catch { process.exitCode = 1; }
  });
});
request.on('timeout', () => request.destroy());
request.on('error', () => { process.exitCode = 1; });
