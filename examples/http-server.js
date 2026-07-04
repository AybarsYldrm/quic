'use strict';

/**
 * examples/http-server.js
 * ────────────────────────────────────────────────────────────────────────
 * A modern HTTP server: HTTP/3 over QUIC as the primary transport, HTTP/2
 * over TCP+TLS as the fallback (advertised via the Alt-Svc header), and a
 * clean 426 Upgrade Required for anything that only speaks HTTP/1.1 or
 * doesn't negotiate ALPN at all (plain TLS probes, scanners, curl without
 * --http2/--http3). This is the same architecture as Http2FallbackGateway +
 * Router used elsewhere in this repo - just trimmed down to a single
 * runnable file.
 *
 * Run:
 *   node examples/http-server.js
 *
 * Then hit it with examples/http-client.js, or with curl:
 *   curl -k --http2 https://localhost:4433/
 *   curl -k --http3 https://localhost:4433/     (needs a curl built with HTTP/3)
 */

const { Http2FallbackGateway, Router } = require('../index');
const { makeDevCert } = require('./_dev-cert');

async function main() {
  const port = Number(process.env.PORT) || 4433;
  const dev = makeDevCert('localhost');

  const app = new Router();

  app.get('/', (req, res) => {
    res.status(200).json({ ok: true, protocol: req.protocol, path: req.url });
  });

  app.get('/echo/:word', (req, res) => {
    res.status(200).json({ word: req.params.word });
  });

  app.use((req, res) => {
    res.status(404).json({ error: 'not_found', path: req.url });
  });

  const gateway = new Http2FallbackGateway({
    port,
    router: app,
    cert: dev.cert,
    key: dev.key,
    // 0x1301 = TLS_AES_128_GCM_SHA256, 0x1303 = TLS_CHACHA20_POLY1305_SHA256.
    // Leave unset to allow both; restrict if you have a reason to (e.g. to
    // match a hardware offload path that only supports one).
  });

  await gateway.listen();
  console.log(`[http-server] listening on https://localhost:${port} (h3 + h2 + 426-for-http/1.1)`);
  console.log(`[http-server] dev CA (pass as { ca } to a client, or rejectUnauthorized:false for quick testing):`);
  console.log(dev.ca);
}

main().catch((err) => {
  console.error('[http-server] fatal:', err);
  process.exit(1);
});
