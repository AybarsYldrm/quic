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
    console.log(`[CONN] Yeni bağlantı: ${conn.remoteAddress}:${conn.remotePort}`);

    conn.on('stream', (stream) => {
      console.log(stream)
      console.log(`[STREAM] #${stream.id} açıldı`);

      const chunks = [];

      stream.on('data', (data) => {
        chunks.push(data);
      });

      stream.on('end', () => {
        const received = Buffer.concat(chunks);
        const text = received.toString();
        console.log(`[STREAM] #${stream.id} -> "${text}"`);

        // Echo back
        const response = `ECHO: ${text}`;
        stream.end(response);
        console.log(`[STREAM] #${stream.id} <- "${response}"`);
      });

      stream.on('error', (err) => {
        console.error(`[STREAM] #${stream.id} hata:`, err.message);
      });
    });

    conn.on('closed', () => {
      console.log(`[CONN] Bağlantı kapandı: ${conn.remoteAddress}:${conn.remotePort}`);
    });
  });

  server.on('error', (err) => {
    console.error('[SERVER] Hata:', err.message);
  });

  const addr = await server.listen(PORT, HOST);
  console.log(`[SERVER] Dinleniyor: ${addr.address}:${addr.port}`);
  console.log(`[SERVER] Cert: ${CERT_PATH}`);
  console.log(`[SERVER] Key:  ${KEY_PATH}`);
  console.log('--- Bağlantı bekleniyor ---\n');
}

main().catch((err) => {
  console.error('Server başlatılamadı:', err);
  process.exit(1);
});