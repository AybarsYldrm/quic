'use strict';

const http2 = require('http2');
const { EventEmitter } = require('events');
const { QuicServer } = require('../server/server');
const { H3Connection } = require('../h3/http3');
const { H2StreamAdapter, Http1RequestAdapter } = require('./h2-adapter');
const { createLogger } = require('../utils/logger');

const log = createLogger('Gateway');

class Http2FallbackGateway extends EventEmitter {
    constructor(options = {}) {
        super();
        this.host = options.host || '0.0.0.0';
        this.port = options.port || 443;
        this.quicPort = options.quicPort || this.port;

        this.cert = options.cert;
        this.key  = options.key;
        this.ca   = options.ca;

        this.router = options.router || null;
        this.h3Alpn = options.h3Alpn || ['h3'];
        this.h2Alpn = options.h2Alpn || ['h2', 'http/1.1'];

        this.altSvc = options.altSvc || `h3=":${this.quicPort}"; ma=86400`;
        this.enableWebTransport = !!options.enableWebTransport;
        this.cipherSuites = options.cipherSuites;
        this.transportParams = options.transportParams || {};
        this.ticketKey = options.ticketKey || null;
    }

    async listen() {
        await Promise.all([this._startQuic(), this._startH2()]);
        log.info(`Gateway Ready: h3/udp:${this.quicPort}, h2/tcp:${this.port}`);
    }

    async _startQuic() {
        this.quicServer = new QuicServer({
            host: this.host,
            port: this.quicPort,
            cert: this.cert,
            key:  this.key,
            alpn: this.h3Alpn,
            cipherSuites: this.cipherSuites,
            transportParams: this.transportParams,
            ticketKey: this.ticketKey,
        });

        this.quicServer.on('connection', (conn) => {
            const h3 = new H3Connection(conn, {
                isServer: true,
                enableWebTransport: this.enableWebTransport,
            });
            
            this.emit('h3connection', h3, conn);

            h3.on('request', (req) => {
                req.transport = 'h3';
                req.quicConn = conn;

                // HTTP/3 routing entry
                const method = (req.method || '').toUpperCase();
                const protocol = req.headers && req.headers[':protocol'];

                // 1. WebTransport CONNECT — never goes through the router
                if (method === 'CONNECT' && protocol === 'webtransport') {
                    try {
                        this.emit('webtransport', req, h3, conn);
                    } catch (err) {
                        log.error('WebTransport handler error:', err.message);
                        try { req.respond(500).end(); } catch (_) {}
                    }
                    return;
                }

                // 2. Regular HTTP/3 requests (GET, POST, ...)
                const chunks = [];
                req.on('data', (c) => chunks.push(c));
                
                req.on('end', () => {
                    req.body = Buffer.concat(chunks);
                    this._dispatch(req);
                });

                // Safety net for body-less requests already complete at attach time
                if (req.stream && req._complete) {
                    req.body = Buffer.concat(chunks);
                    this._dispatch(req);
                }
            });
        });

        await this.quicServer.listen();
    }

    async _startH2() {
        this.h2Server = http2.createSecureServer({
            key:  this.key,
            cert: this.cert,
            allowHTTP1: true,
            ALPNProtocols: this.h2Alpn,
        });

        this.h2Server.on('stream', (stream, headers) => {
            const req = new H2StreamAdapter(stream, headers, { altSvc: this.altSvc });
            if (req._complete) this._dispatch(req);
            else req.once('end', () => this._dispatch(req));
        });

        this.h2Server.on('request', (nreq, nres) => {
            if (nreq.httpVersionMajor !== 1) return;
            const req = new Http1RequestAdapter(nreq, nres, { altSvc: this.altSvc });
            if (req._complete) this._dispatch(req);
            else req.once('end', () => this._dispatch(req));
        });

        this.h2Server.listen(this.port, this.host);
    }

    _dispatch(req) {
        const t0 = process.hrtime.bigint();
        const transport = req.transport || 'h?';
        const method = (req.method || 'GET').toUpperCase();
        const path = req.path || '/';
        const is0RTT = req.quicConn && req.stream && typeof req.quicConn.is0RTT === 'function'
            ? req.quicConn.is0RTT(req.stream.id)
            : false;
        const rttLabel = transport === 'h3' ? (is0RTT ? '0-RTT' : '1-RTT') : transport.toUpperCase();
        const remote = req.quicConn
            ? `${req.quicConn.remoteAddress}:${req.quicConn.remotePort}`
            : (req.stream && req.stream.session && req.stream.session.socket
                ? `${req.stream.session.socket.remoteAddress}:${req.stream.session.socket.remotePort}`
                : '-');

        // Best-effort access log: hook respond() once to capture the
        // status code without changing the response shape.
        const origRespond = req.respond && req.respond.bind(req);
        let loggedStatus = null;
        if (typeof origRespond === 'function') {
            req.respond = (status, headers) => {
                if (loggedStatus === null) loggedStatus = status;
                return origRespond(status, headers);
            };
        }
        const finish = () => {
            const ms = Number(process.hrtime.bigint() - t0) / 1e6;
            const status = loggedStatus !== null ? loggedStatus : '-';
            log.info(`${rttLabel} ${method} ${path} ${status} ${ms.toFixed(1)}ms ${remote}`);
        };
        if (req.stream && typeof req.stream.once === 'function') {
            req.stream.once('finish', finish);
            req.stream.once('close', finish);
        } else if (typeof req.once === 'function') {
            req.once('end', finish);
            req.once('close', finish);
        }

        if (!this.router) {
            try { req.respond(404).end('Router Not Configured'); } catch(_) {}
            return;
        }
        try {
            this.router.handle(req, req.quicConn);
        } catch (err) {
            log.error('Router execution error:', err.message);
            try { req.respond(500).end('Internal Server Error'); } catch(_) {}
        }
    }
}

module.exports = { Http2FallbackGateway };