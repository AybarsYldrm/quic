'use strict';

const path = require('path');
const { QuicServer, QuicClient, SessionTicketStore } = require('../src');

async function run() {
  const cert = path.join(__dirname, '..', 'certs', 'cert.pem');
  const key  = path.join(__dirname, '..', 'certs', 'key.pem');
  const host = '127.0.0.1';
  const port = 9854;
  const store = new SessionTicketStore();

  const server = new QuicServer({
    host,
    port,
    cert,
    key,
    alpn: ['echo'],
  });

  server.on('connection', (conn) => {
    conn.on('stream', (stream) => {
      const chunks = [];
      stream.on('data', (d) => chunks.push(d));
      stream.on('end', () => stream.end(Buffer.concat(chunks)));
    });
  });

  await server.listen();

  const exchange = async (text) => {
    const client = new QuicClient({
      host,
      port,
      serverName: 'nat.intranet.fitfak.net',
      alpn: ['echo'],
      ca: cert,
      rejectUnauthorized: true,
      ticketStore: store,
      connectTimeout: 5000,
    });
    client.on('error', () => {});

    await client.connect();
    const stream = client.createStream(true);

    const response = await new Promise((resolve, reject) => {
      const chunks = [];
      stream.on('data', (d) => chunks.push(d));
      stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      stream.on('error', reject);
      stream.end(text);
    });

    await client.close();
    return response;
  };

  const r1 = await exchange('first');
  const r2 = await exchange('second');

  await server.close();

  if (r1 !== 'first' || r2 !== 'second') {
    throw new Error(`unexpected responses r1=${r1} r2=${r2}`);
  }
  if (store.tickets.size < 1) {
    throw new Error('session ticket was not stored');
  }

  console.log('smoke-ok', { r1, r2, tickets: store.tickets.size });
}

run().catch((err) => {
  console.error('smoke-fail', err.message);
  process.exit(1);
});
