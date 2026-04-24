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

// Sunucu başlarken BİR KEZ oluştur — modül düzeyinde tanımla
const TICKET_KEY = process.env.QUIC_TICKET_KEY
  ? Buffer.from(process.env.QUIC_TICKET_KEY, 'hex')  // Kalıcı key için env'den al
  : crypto.randomBytes(16);                            // Geçici (yeniden başlatmada biletler geçersiz)

console.log('[Server] Ticket key:', TICKET_KEY.toString('hex')); // Doğrulama için


const auth = new AuthService(process.env.JWT_SECRET);
const app = new Router();
const wtServer = new WebTransportServer({ maxSessions: 100 });

const INDEX_HTML = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
const WT_HTML = fs.readFileSync(path.join(__dirname, 'webtransport.html'), 'utf8');

const certData = fs.readFileSync(path.join(__dirname, 'certs', 'cert.pem'), 'utf8');
const keyData  = fs.readFileSync(path.join(__dirname, 'certs', 'key.pem'), 'utf8');

app.use((req, res, next) => {
    res.set('server', 'quic-native/2.0');
    res.set('strict-transport-security', 'max-age=31536000; includeSubDomains; preload');
    res.set('alt-svc', `h3=":${PORT}"; ma=86400`);
    res.set('access-control-allow-origin', '*');
    next();
});

app.get('/', (req, res) => res.html(INDEX_HTML));
app.get('/webtransport', (req, res) => res.html(WT_HTML));

app.post('/api/login', (req, res) => {
    const body = req.json();
    const user = auth.authenticate(body.username, body.password);
    if (user) {
        const token = auth.signJWT({ ...user, exp: Date.now() + 86400000 });
        const cookieToken = Buffer.from(token, 'utf8').toString('hex');
        res.set('Set-Cookie', `access=${cookieToken}; Path=/; HttpOnly; SameSite=Lax; Secure`);
        return res.json({ status: 'success', token });
    }
    res.status(401).json({ status: 'error', message: 'Hatalı giriş' });
});

app.get('/api/me', (req, res) => {
    const cookies = auth.parseCookies(req.headers.cookie || req.headers.Cookie);
    if (cookies.access) {
        try {
            const token = Buffer.from(cookies.access, 'hex').toString('utf8');
            const payload = auth.verifyJWT(token);
            if (payload) return res.json({ status: 'success', user: payload });
        } catch (e) {}
    }
    res.status(401).json({ status: 'error' });
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
    console.log(`🚀 HTTP/3 + WEBTRANSPORT SUNUCUSU AKTİF`);
    console.log(`📡 URL: https://${DOMAIN}:${PORT}`);
    console.log(`───────────────────────────────────────────────────\n`);
}

main().catch(err => {
    console.error("CRITICAL SERVER ERROR:", err);
    process.exit(1);
});