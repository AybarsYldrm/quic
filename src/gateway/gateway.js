'use strict';

const { EventEmitter } = require('events');
const { Server } = require('../server/server'); 
const { WebTransportServer } = require('../webtransport/webtransport');
const { createLogger } = require('../utils/logger');
const log = createLogger('Gateway');

class Http2FallbackGateway extends EventEmitter {
    constructor(options = {}) {
        super();
        this.port = options.port || 443;
        this.host = options.host || '0.0.0.0';
        this.router = options.router;
        
        this.wtServer = options.enableWebTransport 
            ? new WebTransportServer({ maxSessions: 100 }) 
            : null;

        // EKSİK GİDERİLDİ: test.js'den gelen tüm kritik ayarlar Server katmanına aktarılıyor
        this.server = new Server({ 
            cert: options.cert, 
            key: options.key, 
            alpn: options.alpn,
            cipherSuites: options.cipherSuites,
            transportParams: options.transportParams,
            ticketKey: options.ticketKey,
            requireRetry: options.requireRetry
        });
    }

    // EKSİK GİDERİLDİ: Özel H2/H3 motorumuzun req.respond() mimarisine uygun Wrapper
    _wrapResponse(res) {
        // Custom header tutucu
        const headers = {};
        
        // Router tarafındaki standart setHeader çağrılarını yakala
        res.setHeader = (key, value) => {
            headers[key.toLowerCase()] = String(value);
        };

        // Express benzeri res.send() metodunun custom TLS/QUIC stream'ine uyarlanması
        res.send = (data) => {
            const status = res.statusCode || 200;

            if (typeof data === 'string') {
                headers['content-type'] = 'text/plain; charset=utf-8';
                headers['content-length'] = Buffer.byteLength(data);
                res.respond(status, headers);
                res.end(data);
            } else if (typeof data === 'object') {
                const json = JSON.stringify(data);
                headers['content-type'] = 'application/json';
                headers['content-length'] = Buffer.byteLength(json);
                res.respond(status, headers);
                res.end(json);
            } else {
                if (data && data.length) {
                    headers['content-length'] = data.length;
                }
                res.respond(status, headers);
                res.end(data);
            }
        };
        
        return res;
    }

    _setupListeners() {
        // TCP(H2) ve UDP(H3) ortak request event'i
        this.server.on('request', (req) => {
            // req aynı zamanda stream'in kendisidir, bu yüzden res olarak da onu sarmalıyoruz
            this.router.handle(req, this._wrapResponse(req));
        });

        // EKSİK GİDERİLDİ: WebTransport Hook Bağlantısı
        // Server sınıfından fırlatılan yeni QUIC connection'ları yakalayıp WebTransport sunucusuna iletiyoruz
        if (this.wtServer) {
            this.server.on('connection', (quicConn) => {
                // Eğer bağlantıda WebTransport ALPN veya transport parameter tespit edilirse WT sunucusuna devret
                // H3Connection zaten Server içinde oluşturuluyor, buradaki quicConn doğrudan Transport instance'ıdır
                this.wtServer.handleConnect(quicConn);
            });
        }
    }

    async listen() {
        this._setupListeners();
        // Server.listen() zaten TCP ve UDP'yi başlatıyor
        const addr = await this.server.listen(this.port, this.host);
        this.port = addr.port;
        // Bug fixed here: Router defaults altSvcPort to 443 and nothing
        // ever told it otherwise, so every response advertised
        // `alt-svc: h3=":443"` regardless of what port the gateway was
        // actually listening on. Any client on a non-443 port (every dev/
        // test setup, and any deployment behind a different public port)
        // would follow that Alt-Svc hint straight into a dead end.
        if (this.router && typeof this.router.altSvcPort !== 'undefined') {
            this.router.altSvcPort = this.port;
        }
        log.info(`Gateway active on ${this.host}:${this.port} [TCP+UDP]`);
    }
}

module.exports = { Http2FallbackGateway };