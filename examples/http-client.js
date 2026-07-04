'use strict';

/**
 * examples/http-client.js
 * ────────────────────────────────────────────────────────────────────────
 * Talks to examples/http-server.js using the unified HttpClient: the first
 * request races HTTP/3 (QUIC) and HTTP/2 (TCP+TLS) in parallel rather than
 * dialing them one after another, and remembers per-origin which protocol
 * won (or what the response's Alt-Svc header advertised) so every request
 * after that goes straight to QUIC.
 *
 * Run (with examples/http-server.js already running):
 *   node examples/http-client.js
 *
 * Or against your own server:
 *   node examples/http-client.js https://your-host:443 /some/path
 */

const { HttpClient } = require('../index');

async function main() {
  const url = process.argv[2] || 'https://localhost:4433/';

  const client = new HttpClient({
    // This example's server uses a throwaway self-signed dev cert, so
    // there's nothing for us to validate trust against. Against a real
    // deployment, drop rejectUnauthorized entirely (it defaults to true)
    // and let it verify against the real certificate chain.
    rejectUnauthorized: false,
    timeout: 5000,
  });

  console.log(`[http-client] first request to ${url} (races h2 + h3)...`);
  const first = await client.request(url);
  console.log(`[http-client] -> ${first.status} via ${first.protocol}: ${first.body.toString()}`);

  console.log(`[http-client] second request to the same origin (should reuse the pooled connection)...`);
  const second = await client.request(url);
  console.log(`[http-client] -> ${second.status} via ${second.protocol}: ${second.body.toString()}`);

  await client.close();
}

main().catch((err) => {
  console.error('[http-client] fatal:', err);
  process.exit(1);
});
