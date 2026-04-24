'use strict';

const { QuicClient } = require('../src/index');

const HOST        = process.argv[2] || process.env.QUIC_HOST || 'nat.intranet.fitfak.net';
const PORT        = parseInt(process.argv[3] || process.env.QUIC_PORT || '7844', 10);
const SERVER_NAME = process.argv[4] || process.env.QUIC_SNI  || 'nat.intranet.fitfak.net';
const MESSAGE     = process.argv[5] || 'Hello QUIC! Bu mesaj RFC 9000 uyumlu QUIC üzerinden gönderildi.';

async function main() {
  console.log('=== QUIC Client - RFC 9000/9001/9002 ===\n');
  console.log(`[CLIENT] Hedef: ${HOST}:${PORT} (SNI: ${SERVER_NAME})`);

  const client = new QuicClient({
    host: HOST,
    port: PORT,
    serverName: SERVER_NAME,
    alpn: ['h3'],
    transportParams: {
      maxIdleTimeout: 30000,
      initialMaxData: 1048576,
      initialMaxStreamDataBidiLocal: 262144,
      initialMaxStreamDataBidiRemote: 262144,
      initialMaxStreamsBidi: 100,
    },
  });

  client.on('error', (err) => {
    console.error('[CLIENT] Hata:', err.message);
  });

  try {
    console.log('[CLIENT] Bağlanılıyor...');
    const conn = await client.connect();
    console.log('[CLIENT] Bağlantı kuruldu!\n');

    const stream = client.createStream(true);
    console.log(`[CLIENT] Stream #${stream.id} oluşturuldu`);

    stream.end(MESSAGE);
    console.log(`[CLIENT] Gönderildi: "${MESSAGE}"`);

    const chunks = [];
    stream.on('data', (data) => {
      chunks.push(data);
    });

    stream.on('end', () => {
      const response = Buffer.concat(chunks);
      console.log(`\n[CLIENT] Yanıt: "${response.toString()}"`);

      setTimeout(async () => {
        await client.close(0, 'done');
        console.log('[CLIENT] Bağlantı kapatıldı');
        console.log('[CLIENT] İstatistik:', client.stats);
        process.exit(0);
      }, 200);
    });

    setTimeout(() => {
      console.log('\n[TIMEOUT] 15 saniye içinde yanıt alınamadı');
      console.log('[CLIENT] İstatistik:', client.stats);
      process.exit(1);
    }, 15000);

  } catch (err) {
    console.error('[CLIENT] Bağlantı kurulamadı:', err.message);
    process.exit(1);
  }
}

main().catch(console.error);