'use strict';

const { QuicClient, H3Connection, Http3Client } = require('./src/index');

const HOST        = process.argv[2] || 'nat.intranet.fitfak.net';
const PORT        = parseInt(process.argv[3] || '443', 10);
const SERVER_NAME = process.argv[4] || HOST;
const REQ_PATH    = process.argv[5] || '/';
const MODE        = process.argv[6] || 'low'; // 'low' = low-level, 'high' = high-level client

async function lowLevelDemo() {
  console.log('=== HTTP/3 Client (Low-Level) ===\n');
  console.log(`Target: https://${SERVER_NAME}:${PORT}${REQ_PATH}\n`);

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
      initialMaxStreamsUni: 100,
    },
  });

  client.on('error', (err) => {
    // QuicClient already rejects connect() with this error, so just log
    // post-connect failures (e.g. peer-initiated CONNECTION_CLOSE).
    console.error('[CLIENT] Error:', err.message);
  });

  try {
    console.log('[CLIENT] Connecting via QUIC...');
    const conn = await client.connect();
    console.log('[CLIENT] QUIC connection established');

    const h3 = new H3Connection(conn, { isServer: false });

    h3.on('ready', () => {
      console.log('[H3] Session ready, sending request...\n');

      const req = h3.request('GET', REQ_PATH, {
        'accept': '*/*',
        'user-agent': 'quic-native-h3/2.0',
      }, {
        authority: SERVER_NAME,
      });

      req.endRequest();

      req.on('headers', (headers) => {
        console.log(`[H3] Response: ${req.status}`);
        console.log('[H3] Headers:', headers);
      });

      const bodyChunks = [];
      req.on('data', (chunk) => bodyChunks.push(chunk));

      req.on('end', async () => {
        const body = Buffer.concat(bodyChunks).toString();
        console.log(`\n[H3] Body (${Buffer.byteLength(body)} bytes):`);
        console.log('-'.repeat(50));
        console.log(body.substring(0, 2000));
        if (body.length > 2000) console.log(`... (${body.length - 2000} more bytes)`);
        console.log('-'.repeat(50));

        // Send second request
        if (REQ_PATH === '/') {
          console.log('\n[H3] Sending /api/info request...\n');
          const req2 = h3.request('GET', '/api/info', {
            'accept': 'application/json',
          }, { authority: SERVER_NAME });
          req2.endRequest();

          const chunks2 = [];
          req2.on('data', (chunk) => chunks2.push(chunk));
          req2.on('end', async () => {
            console.log('[H3] /api/info:', Buffer.concat(chunks2).toString());
            await client.close(0, 'done');
            console.log('\n[CLIENT] Connection closed. Stats:', client.stats);
            process.exit(0);
          });
        } else {
          await client.close(0, 'done');
          console.log('\n[CLIENT] Connection closed. Stats:', client.stats);
          process.exit(0);
        }
      });
    });

    setTimeout(() => {
      console.log('\n[TIMEOUT] 15s timeout');
      process.exit(1);
    }, 15000);

  } catch (err) {
    console.error('[CLIENT] Connection failed:', err.message);
    process.exit(1);
  }
}

async function highLevelDemo() {
  console.log('=== HTTP/3 Client (High-Level, axios-like) ===\n');
  console.log(`Target: https://${SERVER_NAME}:${PORT}${REQ_PATH}\n`);

  const client = new Http3Client({
    timeout: 10000,
    headers: {
      'user-agent': 'quic-native-h3/2.0',
    },
  });

  try {
    // Simple GET request
    console.log('[GET] Fetching...');
    const res = await client.get(`https://${SERVER_NAME}:${PORT}${REQ_PATH}`);
    console.log(`[GET] Status: ${res.status} (${res.protocol})`);
    console.log(`[GET] Headers:`, res.headers);
    const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
    console.log(`[GET] Body: ${body.substring(0, 500)}`);

    // JSON API request
    console.log('\n[GET] /api/info...');
    const res2 = await client.get(`https://${SERVER_NAME}:${PORT}/api/info`);
    console.log(`[GET] Status: ${res2.status}`);
    console.log(`[GET] Data:`, res2.data);

    await client.close();
    console.log('\n[CLIENT] Done');
    process.exit(0);

  } catch (err) {
    console.error('[CLIENT] Error:', err.message);
    await client.close();
    process.exit(1);
  }
}

if (MODE === 'high') {
  highLevelDemo().catch(console.error);
} else {
  lowLevelDemo().catch(console.error);
}
