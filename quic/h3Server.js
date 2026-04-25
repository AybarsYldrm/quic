'use strict';

const path = require('path');
const fs = require('fs');
const { 
    Http2FallbackGateway, 
    Router, 
    WebTransportServer 
} = require('./src/index');
const { AuthService } = require('./src/server/authorization');

const HOST = process.env.QUIC_HOST || '185.95.164.233';
const PORT = parseInt(process.env.QUIC_PORT || '443', 10);
const DOMAIN = process.env.DOMAIN || HOST;
const crypto = require('crypto');

// Persistent across restarts iff QUIC_TICKET_KEY is set; otherwise issued
// tickets become invalid on restart (clients fall back to full handshake).
const TICKET_KEY = process.env.QUIC_TICKET_KEY
  ? Buffer.from(process.env.QUIC_TICKET_KEY, 'hex')
  : crypto.randomBytes(16);


const auth = new AuthService(process.env.JWT_SECRET);
const app = new Router();
const wtServer = new WebTransportServer({ maxSessions: 100 });

const INDEX_HTML = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
const WT_HTML    = fs.readFileSync(path.join(__dirname, 'webtransport.html'), 'utf8');
const INDEX_ETAG = `"${crypto.createHash('sha1').update(INDEX_HTML).digest('hex').slice(0, 16)}"`;
const WT_ETAG    = `"${crypto.createHash('sha1').update(WT_HTML).digest('hex').slice(0, 16)}"`;
const STATIC_CACHE_CONTROL = 'public, max-age=300, must-revalidate';

// Conditional-request short-circuit: 304 Not Modified when ETag matches.
function serveStatic(req, res, body, etag) {
    res.set('etag', etag);
    res.set('cache-control', STATIC_CACHE_CONTROL);
    res.set('vary', 'Accept-Encoding');
    if (req.headers['if-none-match'] === etag) {
        res.set('content-length', '0');
        return res.status(304).end();
    }
    res.html(body);
}

const certData = fs.readFileSync(path.join(__dirname, 'certs', 'cert.pem'), 'utf8');
const keyData  = fs.readFileSync(path.join(__dirname, 'certs', 'key.pem'), 'utf8');

app.use((req, res, next) => {
    res.set('server', 'quic-native/2.0');
    res.set('strict-transport-security', 'max-age=31536000; includeSubDomains; preload');
    res.set('alt-svc', `h3=":${PORT}"; ma=86400`);
    res.set('access-control-allow-origin', '*');
    next();
});

app.get('/', (req, res) => serveStatic(req, res, INDEX_HTML, INDEX_ETAG));
app.get('/webtransport', (req, res) => serveStatic(req, res, WT_HTML, WT_ETAG));

app.post('/api/login', (req, res) => {
    const body = req.json();
    if (!body) return res.status(400).json({ status: 'error', message: 'Invalid request' });
    const user = auth.authenticate(body.username, body.password);
    if (user) {
        const token = auth.signJWT({ ...user, exp: Date.now() + 86400000 });
        res.set('Set-Cookie', `access=${token}; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax; Secure`);
        return res.json({ status: 'success', token, user });
    }
    res.status(401).json({ status: 'error', message: 'Invalid credentials' });
});

app.get('/api/me', (req, res) => {
    const cookies = auth.parseCookies(req.headers.cookie || req.headers.Cookie);
    if (cookies.access) {
        try {
            const payload = auth.verifyJWT(cookies.access);
            if (payload) return res.json({ status: 'success', token: cookies.access, user: payload });
        } catch (e) {}
    }
    res.status(401).json({ status: 'error' });
});

app.post('/api/logout', (req, res) => {
    res.set('Set-Cookie', 'access=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure');
    res.json({ status: 'success' });
});

// =====================================================================
// WEBTRANSPORT SERVER (Senin Eski Kodundaki Kusursuz Yankı Sistemi)
// =====================================================================
wtServer.on('session', (session) => {
    console.log(`[WebTransport] New session: ${session.id}`);

    // Auto-accept all sessions
    session.accept({ 'access-control-allow-origin': '*' });

    // Echo datagrams back to all other sessions
    session.on('datagram', (data) => {
        for (const [, otherSession] of wtServer.sessions) {
            if (otherSession !== session && otherSession.state === 'connected') {
                otherSession.sendDatagram(data);
            }
        }
    });

    // Handle bidirectional streams (echo)
    session.on('bidiStream', (stream) => {
        stream.on('data', (chunk) => {
            stream.write(chunk); // echo back
        });
    });

    session.on('closed', () => {
        console.log(`[WebTransport] Session ${session.id} closed. Active: ${wtServer.sessions.size}`);
    });
});

async function main() {
    const gateway = new Http2FallbackGateway({
        host: HOST,
        port: PORT,
        cert: certData,
        key:  keyData,
        ticketKey: TICKET_KEY,
        router: app,
        enableWebTransport: true,
        cipherSuites: ['CHACHA20'],
        transportParams: {
            maxIdleTimeout: 30000,
            initialMaxData: 1073741824,
            initialMaxStreamsBidi: 1000,
            initialMaxStreamsUni: 100,
            initialMaxStreamDataBidiLocal: 10485760,
            initialMaxStreamDataBidiRemote: 10485760,
            initialMaxStreamDataUni: 10485760,
            activeConnectionIdLimit: 8,
            maxDatagramFrameSize: 65535
        }
    });

    // WebTransport Gateway Köprüsü
    gateway.on('webtransport', (req, h3, quicConn) => {
        wtServer.handleConnect(req, h3, quicConn);
    });

    await gateway.listen();
    console.log(`\n───────────────────────────────────────────────────`);
    console.log(`HTTP/3 + WebTransport server is up`);
    console.log(`📡 URL: https://${DOMAIN}:${PORT}`);
    console.log(`───────────────────────────────────────────────────\n`);
}

main().catch(err => {
    console.error("CRITICAL SERVER ERROR:", err);
    process.exit(1);
});