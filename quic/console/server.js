'use strict';

const path = require('path');
const { QuicServer } = require('../src/index');

const CERT_PATH = process.env.QUIC_CERT || path.join(__dirname, 'certs', 'cert.pem');
const KEY_PATH  = process.env.QUIC_KEY  || path.join(__dirname, 'certs', 'key.pem');
const PORT      = parseInt(process.env.QUIC_PORT || '7844', 10);
const HOST      = process.env.QUIC_HOST || '185.95.164.233';

async function main() {
  console.log('=== QUIC Server - RFC 9000/9001/9002 ===\n');

  const server = new QuicServer({
    port: PORT,
    host: HOST,
    cert: CERT_PATH,
    key: KEY_PATH,
    alpn: ['echo'],
    transportParams: {
      maxIdleTimeout: 30000,
      initialMaxData: 1048576,
      initialMaxStreamDataBidiLocal: 262144,
      initialMaxStreamDataBidiRemote: 262144,
      initialMaxStreamsBidi: 100,
      initialMaxStreamsUni: 100,
    },
  });

  server.on('connection', (conn) => {
    console.log(`[CONN] new: ${conn.remoteAddress}:${conn.remotePort}`);

    conn.on('stream', (stream) => {
      console.log(`[STREAM] #${stream.id} opened`);

      const chunks = [];

      stream.on('data', (data) => chunks.push(data));

      stream.on('end', () => {
        const text = Buffer.concat(chunks).toString();
        console.log(`[STREAM] #${stream.id} -> "${text}"`);

        const response = `ECHO: ${text}`;
        stream.end(response);
        console.log(`[STREAM] #${stream.id} <- "${response}"`);
      });

      stream.on('error', (err) => {
        console.error(`[STREAM] #${stream.id} error:`, err.message);
      });
    });

    conn.on('closed', () => {
      console.log(`[CONN] closed: ${conn.remoteAddress}:${conn.remotePort}`);
    });
  });

  server.on('error', (err) => {
    console.error('[SERVER] error:', err.message);
  });

  const addr = await server.listen(PORT, HOST);
  console.log(`[SERVER] listening on ${addr.address}:${addr.port}`);
  console.log(`[SERVER] cert: ${CERT_PATH}`);
  console.log(`[SERVER] key:  ${KEY_PATH}`);
  console.log('--- waiting for connections ---\n');
}

main().catch((err) => {
  console.error('Server failed to start:', err);
  process.exit(1);
});