'use strict';

const { QuicClient } = require('../src/index');

const HOST        = process.argv[2] || process.env.QUIC_HOST || 'nat.intranet.fitfak.net';
const PORT        = parseInt(process.argv[3] || process.env.QUIC_PORT || '7844', 10);
const SERVER_NAME = process.argv[4] || process.env.QUIC_SNI  || 'nat.intranet.fitfak.net';
const MESSAGE     = process.argv[5] || 'Hello QUIC! This message was sent over an RFC 9000 compliant QUIC channel.';

async function main() {
  console.log('=== QUIC Client - RFC 9000/9001/9002 ===\n');
  console.log(`[CLIENT] Hedef: ${HOST}:${PORT} (SNI: ${SERVER_NAME})`);

  const client = new QuicClient({
    host: HOST,
    port: PORT,
    serverName: SERVER_NAME,
    alpn: ['h3'],
    connectTimeout: 15000,
    transportParams: {
      maxIdleTimeout: 30000,
      initialMaxData: 1048576,
      initialMaxStreamDataBidiLocal: 262144,
      initialMaxStreamDataBidiRemote: 262144,
      initialMaxStreamsBidi: 100,
    },
  });

  client.on('error', (err) => {
    // QuicClient.connect() rejects with this same error; this listener
    // catches late errors (peer-initiated CONNECTION_CLOSE, network drop).
    console.error('[CLIENT] error:', err.message);
  });

  try {
    console.log('[CLIENT] connecting...');
    const conn = await client.connect();
    console.log('[CLIENT] connected\n');

    const stream = client.createStream(true);
    console.log(`[CLIENT] opened stream #${stream.id}`);

    stream.end(MESSAGE);
    console.log(`[CLIENT] sent: "${MESSAGE}"`);

    const chunks = [];
    stream.on('data', (data) => chunks.push(data));

    stream.on('end', () => {
      const response = Buffer.concat(chunks);
      console.log(`\n[CLIENT] reply: "${response.toString()}"`);

      setTimeout(async () => {
        await client.close(0, 'done');
        console.log('[CLIENT] connection closed');
        console.log('[CLIENT] stats:', client.stats);
        process.exit(0);
      }, 200);
    });

    setTimeout(() => {
      console.log('\n[TIMEOUT] no reply within 15 s');
      console.log('[CLIENT] stats:', client.stats);
      process.exit(1);
    }, 15000);

  } catch (err) {
    console.error('[CLIENT] connect failed:', err.message);
    process.exit(1);
  }
}

main().catch(console.error);