'use strict';

/**
 * examples/quic-raw-client.js
 * ────────────────────────────────────────────────────────────────────────
 * Dials examples/quic-raw-server.js with connectQuic(..., { http3: false }).
 * With http3:false, connectQuic() does the QUIC handshake and nothing more -
 * no H3Connection is created, so `conn.h3` is null and `conn.fetch` isn't
 * defined. What you get instead is `conn.transport` (the QuicConnection
 * facade) plus a couple of shortcuts on `conn` itself: createStream(),
 * sendDatagram(), and on() for 'stream'/'datagram'/etc events - everything
 * you need to speak your own framing directly over QUIC.
 *
 * Run (with examples/quic-raw-server.js already running):
 *   node examples/quic-raw-client.js
 */

const { connectQuic } = require('../index');

async function main() {
  const host = process.argv[2] || 'localhost';
  const port = Number(process.argv[3]) || 4434;

  const conn = await connectQuic(host, port, {
    alpn: ['my-raw-proto/1'],
    http3: false,
    // See examples/http-client.js's note on rejectUnauthorized - this is
    // only safe because we know it's talking to our own throwaway dev cert.
    rejectUnauthorized: false,
    timeout: 5000,
  });
  console.log(`[quic-raw-client] connected to ${host}:${port} (raw QUIC, no HTTP/3)`);

  const stream = conn.createStream(true);
  stream.write(Buffer.from('hello over raw quic'));
  stream.end();

  let response = Buffer.alloc(0);
  stream.on('data', (chunk) => { response = Buffer.concat([response, chunk]); });
  stream.on('end', () => {
    console.log(`[quic-raw-client] stream response: ${response.toString()}`);

    conn.sendDatagram(Buffer.from('a one-off unreliable datagram'));

    setTimeout(() => {
      conn.close();
      console.log('[quic-raw-client] done');
    }, 100);
  });
}

main().catch((err) => {
  console.error('[quic-raw-client] fatal:', err);
  process.exit(1);
});
