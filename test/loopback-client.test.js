'use strict';

/**
 * Loopback end-to-end smoke test for the new client dialers.
 * Not wired into any test runner - just `node test/loopback-client.test.js`.
 * Spins up the project's own Server (h3+h2+http1.1) with a locally-issued
 * EC certificate and drives it with connectQuic / connectHttp2 / HttpClient.
 */

const assert = require('assert');
const { Server } = require('../src/server/server');
const { connectQuic } = require('../src/client/quic-client');
const { connectHttp2 } = require('../src/client/http2-client');
const { HttpClient } = require('../src/client/http-client');
const {
  generateEcRootCA, generateEcEndEntityCert, ecPrivToPem,
} = require('@fitfak/ssl');

async function main() {
  const rootCA = generateEcRootCA();
  const leaf   = generateEcEndEntityCert(rootCA, 'localhost');
  const certPem = leaf.certPem;
  const keyPem  = ecPrivToPem(leaf);

  const server = new Server({
    cert: certPem,
    key:  keyPem,
    alpn: ['h3', 'h2', 'http/1.1'],
  });

  server.on('request', (req) => {
    let body = '';
    req.on('data', (c) => { body += c.toString(); });
    req.on('end', () => {
      req.set('content-type', 'text/plain; charset=utf-8');
      req.respond(200, {});
      req.end(`hello via ${req.protocol} path=${req.path}`);
    });
  });
  server.on('error', (err) => console.error('[server error]', err.message));

  const { port } = await server.listen(0, '127.0.0.1');
  console.log(`[test] server listening on 127.0.0.1:${port}`);

  const commonOpts = { ca: rootCA.certPem, rejectUnauthorized: true, timeout: 5000 };

  // 1. Direct QUIC/H3 dial
  console.log('\n=== [1] connectQuic ===');
  const q1 = await connectQuic('localhost', port, commonOpts);
  const r1 = await new Promise((resolve, reject) => {
    const req = q1.h3.request('GET', '/quic-direct', {}, { authority: 'localhost', endStream: true });
    let body = '';
    req.on('data', (c) => body += c.toString());
    req.on('end', () => resolve({ status: req.status, body }));
    req.on('error', reject);
  });
  console.log('[test] h3 direct response:', r1);
  assert.strictEqual(r1.status, 200);
  assert.match(r1.body, /hello via h3/);
  console.log('PASS: direct QUIC/HTTP3 client dial + request/response');

  // 2. Direct TCP+TLS/H2 dial
  console.log('\n=== [2] connectHttp2 ===');
  const q2 = await connectHttp2('localhost', port, commonOpts);
  const r2 = await new Promise((resolve, reject) => {
    const req = q2.h2.request('GET', '/h2-direct', {}, { authority: 'localhost', endStream: true });
    let body = '';
    req.on('data', (c) => body += c.toString());
    req.on('end', () => resolve({ status: req.status, body }));
    req.on('error', reject);
  });
  console.log('[test] h2 direct response:', r2);
  assert.strictEqual(r2.status, 200);
  assert.match(r2.body, /hello via h2/);
  console.log('PASS: direct HTTP/2 (TCP+TLS) client dial + request/response');

  // 3. Certificate validation actually rejects an untrusted server
  console.log('\n=== [3] certificate validation must reject unknown CA ===');
  let rejected = false;
  try {
    await connectHttp2('localhost', port, { rejectUnauthorized: true, timeout: 3000 }); // no `ca` supplied
  } catch (e) {
    rejected = true;
    console.log('[test] correctly rejected:', e.message);
  }
  assert.ok(rejected, 'connection without trusted CA should have been rejected');
  console.log('PASS: client refuses to trust an unverifiable certificate by default');

  // 4. Unified HttpClient: races h2+h3, caches Alt-Svc/connections
  console.log('\n=== [4] HttpClient race + reuse ===');
  const client = new HttpClient(commonOpts);
  const res1 = await client.request(`https://localhost:${port}/race-1`);
  console.log('[test] race response 1:', res1.status, res1.protocol, res1.body.toString());
  assert.strictEqual(res1.status, 200);

  const res2 = await client.request(`https://localhost:${port}/race-2`);
  console.log('[test] race response 2:', res2.status, res2.protocol, res2.body.toString());
  assert.strictEqual(res2.status, 200);
  console.log('PASS: unified HttpClient (happy-eyeballs h2/h3 race) works end-to-end');

  await client.close();
  q1.close();
  q2.close();
  await server.close();
  console.log('\nALL TESTS PASSED');
  process.exit(0);
}

main().catch((err) => {
  console.error('\nTEST FAILED:', err);
  process.exit(1);
});
