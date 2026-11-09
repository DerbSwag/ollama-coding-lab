import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';

export function createApp() {
  return createServer((request, response) => {
    response.setHeader('Content-Type', 'application/json; charset=utf-8');
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    if (request.method !== 'GET') {
      response.writeHead(405, { Allow: 'GET' });
      response.end(JSON.stringify({ error: 'method_not_allowed' }));
      return;
    }
    let path;
    try { path = new URL(request.url, 'http://localhost').pathname; }
    catch {
      response.writeHead(400);
      response.end(JSON.stringify({ error: 'bad_request' }));
      return;
    }
    if (path === '/') {
      response.end(JSON.stringify({ service: 'ollama-coding-lab-demo', version: '1.0.0' }));
    } else if (path === '/health') {
      response.end(JSON.stringify({ status: 'ok' }));
    } else {
      response.writeHead(404);
      response.end(JSON.stringify({ error: 'not_found' }));
    }
  });
}

export function startServer(env = process.env) {
  const port = Number(env.PORT ?? 3000);
  if (!Number.isInteger(port) || port < 0 || port > 65535 || env.PORT === '') {
    throw new Error('PORT must be an integer between 0 and 65535');
  }
  const server = createApp();
  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;
  server.on('error', () => {
    console.error(JSON.stringify({ event: 'startup_error' }));
    process.exitCode = 1;
  });
  let stopping = false;
  const shutdown = () => {
    if (stopping) return;
    stopping = true;
    console.log(JSON.stringify({ event: 'shutdown' }));
    server.close(() => {
      clearTimeout(deadline);
      process.removeListener('SIGTERM', shutdown);
      process.removeListener('SIGINT', shutdown);
    });
    const deadline = setTimeout(() => {
      server.closeAllConnections();
      process.exitCode = 1;
    }, 5_000);
    deadline.unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
  server.listen(port, '0.0.0.0', () => {
    console.log(JSON.stringify({ event: 'listening', port: server.address().port }));
  });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { startServer(); }
  catch {
    console.error(JSON.stringify({ event: 'invalid_configuration' }));
    process.exitCode = 1;
  }
}
