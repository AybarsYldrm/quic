'use strict';

/**
 * examples/quic-raw-server.js
 * ────────────────────────────────────────────────────────────────────────
 * Plain QUIC, no HTTP/3 and no TCP fallback - useful if you're running your
 * own framing/protocol directly over QUIC streams and datagrams instead of
 * HTTP. `enableH3:false` stops the server from attaching an H3Connection to
 * every accepted connection (which would otherwise try to parse your raw
 * stream bytes as HTTP/3 frames); `enableTcp:false` skips the TCP listener
 * entirely, so this binds UDP only. Version negotiation, Retry, anti-
 * amplification and connection-ID handling all still happen exactly as they
 * do for the HTTP-serving Server - only the framing above QUIC changes.
 *
 * Run:
 *   node examples/quic-raw-server.js
 * Then:
 *   node examples/quic-raw-client.js
 */

const { Server } = require('../index');
const { makeDevCert } = require('./_dev-cert');

async function main() {
  const port = Number(process.env.PORT) || 4434;
  const dev = makeDevCert('localhost');

  const server = new Server({
    port,
    cert: dev.cert,
    key: dev.key,
    alpn: ['my-raw-proto/1'], // any ALPN token your client and server agree on
    enableH3: false,
    enableTcp: false,
  });

  server.on('connection', (transport) => {
    console.log('[quic-raw-server] connection established');

    transport.on('stream', (stream) => {
      let received = Buffer.alloc(0);
      stream.on('data', (chunk) => { received = Buffer.concat([received, chunk]); });
      stream.on('end', () => {
        console.log(`[quic-raw-server] stream ${stream.id}: received ${received.length} bytes: ${received.toString()}`);
        stream.write(Buffer.concat([Buffer.from('echo: '), received]));
        stream.end();
      });
    });

    // RFC 9221 unreliable datagrams are available too, if your protocol
    // wants "send it now, don't bother retransmitting" semantics:
    transport.on('datagram', (data) => {
      console.log(`[quic-raw-server] datagram: ${data.toString()}`);
    });

    transport.on('closed', () => console.log('[quic-raw-server] connection closed'));
  });

  server.on('error', (err) => console.error('[quic-raw-server] error:', err.message));

  const addr = await server.listen(port, '0.0.0.0');
  console.log(`[quic-raw-server] listening on udp://0.0.0.0:${addr.port} (ALPN: my-raw-proto/1)`);
  console.log('[quic-raw-server] dev CA:');
  console.log(dev.ca);
}

main().catch((err) => {
  console.error('[quic-raw-server] fatal:', err);
  process.exit(1);
});
