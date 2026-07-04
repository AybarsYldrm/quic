'use strict';

const net    = require('net');
const dgram  = require('dgram');
const fs     = require('fs');
const crypto = require('crypto');
const { EventEmitter } = require('events');

const {
  QUIC_VERSION_1, PACKET_TYPE, MIN_INITIAL_PACKET_SIZE,
  INITIAL_TOKEN_LIFETIME,
} = require('../constants');

const { parsePacketHeader, buildVersionNegotiation } = require('../packet/codec');
const {
  generateConnectionId, generateToken, validateToken,
  computeRetryIntegrityTag,
} = require('../crypto/crypto');
const { SessionTicketStore } = require('../crypto/zero-rtt');
const { CertificateValidator } = require('../crypto/cert-validator');

const { TLS, ENCRYPTION_LEVEL }  = require('../crypto/tls');
const { H3Connection }           = require('../h3/http3');
const { Transport }              = require('../connection/connection');

const { createLogger } = require('../utils/logger');
const log = createLogger('Server');

// Bug fixed here: this used to be `cipher.includes('256') ? 'aes-256-gcm' :
// 'aes-128-gcm'`, which silently mapped a negotiated chacha20-poly1305
// suite onto aes-128-gcm - a 16-byte-key algorithm being fed a 32-byte
// chacha20 key, which Node's crypto module rejects outright.
function _tlsAeadAlgo(cipherName) {
  if (cipherName === 'chacha20-poly1305') return 'chacha20-poly1305';
  return cipherName && cipherName.includes('256') ? 'aes-256-gcm' : 'aes-128-gcm';
}

class TcpH2Session extends EventEmitter {
  constructor(socket, tlsOpts = {}) {
    super();
    this.socket  = socket;
    this._closed = false;

    this.tls = new TLS({
      transport:          'tcp',
      isServer:           true,
      cert:               tlsOpts.cert,
      key:                tlsOpts.key,
      alpn:               tlsOpts.alpn || ['h2', 'http/1.1'],
      cipherSuites:       tlsOpts.cipherSuites,
      requestCert:        tlsOpts.requestCert        || false,
      rejectUnauthorized: tlsOpts.rejectUnauthorized || false,
      ca:                 tlsOpts.ca                 || null,
      sessionManager:     tlsOpts.sessionManager     || null,
    });

    this._recvBuf       = Buffer.alloc(0);
    this._sendKeys      = null;
    this._recvKeys      = null;
    this._seqSend       = 0n;
    this._seqRecv       = 0n;
    this._handshakeDone = false;
    this._h2FrameParser = null;
    this._h2            = null;
    this._alpn          = null;

    this._wireTLS();
    this._wireSocket();
  }

  _wireTLS() {
    this.tls.onHandshakeData = (typeOrCmd, data, encrypted) => {
      if (typeOrCmd === 'SET_WRITE_KEYS') { this._sendKeys = data; this._seqSend = 0n; return; }
      if (typeOrCmd === 'SET_READ_KEYS')  { this._recvKeys = data; this._seqRecv = 0n; return; }
      if (typeOrCmd === 'CCS')            { this._writeRaw(Buffer.from([0x14, 0x03, 0x03, 0x00, 0x01, 0x01])); return; }
      const record = encrypted ? this._encryptRecord(22, data) : this._plaintextRecord(22, data);
      this._writeRaw(record);
    };

    this.tls.onSecure = (info) => {
      this._handshakeDone = true;
      this._alpn = info.alpn || null;
      
      // YENİ: ALPN kontrolü ve zarif HTTP/1.1 reddi
      if (this._alpn === 'h2') {
        log.info(`[TCP] TLS 1.3 handshake complete: ALPN=h2, cipher=${info.cipher}`);
        this._startH2();
      } else {
        // Port tarayıcıları (Scanners) veya HTTP/1.1 istemcileri
        log.debug(`[TCP] Handshake successful but no H2 ALPN negotiated (ALPN: ${this._alpn || 'null'}). Rejecting gracefully.`);
        
        // H2 destelemeyen istemcilere HTTP/1.1 426 Upgrade Required dönüp kapatıyoruz
        const fallbackMsg = "HTTP/1.1 426 Upgrade Required\r\nConnection: close\r\nUpgrade: h2, h3\r\n\r\nThis server requires HTTP/2 or HTTP/3.";
        const encryptedResponse = this._encryptRecord(23, Buffer.from(fallbackMsg));
        this._writeRaw(encryptedResponse);
        
        // Verinin iletilmesi için ufak bir pay bırakıp soketi kapatıyoruz
        setTimeout(() => this._closeSocket(), 50);
      }
    };

    this.tls.onError = (err) => { 
      // YENİ: Scanner'lar yanlış paket yolladığında WARN basmasını engellemek için DEBUG'a çekildi
      log.debug(`[TCP] TLS error (Scanner/Bot?): ${err.message}`); 
      this._closeSocket(); 
      this.emit('error', err); 
    };
  }

  _wireSocket() {
    this.socket.on('data',  (chunk) => this._onRawData(chunk));
    this.socket.on('end',   ()      => { if (this._h2) this._h2.emit('end'); else this.emit('end'); });
    this.socket.on('error', (err)   => { if (this._h2) this._h2.emit('error', err); else this.emit('error', err); });
    this.socket.on('close', ()      => this._cleanup());
  }

  _onRawData(chunk) {
    this._recvBuf = Buffer.concat([this._recvBuf, chunk]);
    while (this._recvBuf.length >= 5) {
      const contentType = this._recvBuf[0];
      const length      = this._recvBuf.readUInt16BE(3);
      if (this._recvBuf.length < 5 + length) break;
      const payload = this._recvBuf.subarray(5, 5 + length);
      this._recvBuf = this._recvBuf.subarray(5 + length);
      this._handleRecord(contentType, payload);
    }
  }

  _buildNonce(baseIv, seq) {
    const nonce  = Buffer.from(baseIv);
    const seqBuf = Buffer.alloc(8);
    seqBuf.writeBigUInt64BE(seq);
    for (let i = 0; i < 8; i++) nonce[nonce.length - 8 + i] ^= seqBuf[i];
    return nonce;
  }

  _encryptRecord(contentType, plaintext) {
    if (!this._sendKeys) return this._plaintextRecord(contentType, plaintext);
    const { key, iv, cipher } = this._sendKeys;
    const nonce    = this._buildNonce(iv, this._seqSend++);
    const inner    = Buffer.concat([plaintext, Buffer.from([contentType])]);
    const cipherFn = _tlsAeadAlgo(cipher);
    const enc      = crypto.createCipheriv(cipherFn, key, nonce, { authTagLength: 16 });
    const aad      = Buffer.from([0x17, 0x03, 0x03, 0x00, 0x00]);
    aad.writeUInt16BE(inner.length + 16, 3);
    enc.setAAD(aad);
    const body   = Buffer.concat([enc.update(inner), enc.final(), enc.getAuthTag()]);
    const header = Buffer.alloc(5);
    header[0] = 23; header[1] = 0x03; header[2] = 0x03;
    header.writeUInt16BE(body.length, 3);
    return Buffer.concat([header, body]);
  }

  _handleRecord(contentType, payload) {
    if (contentType === 20) return;
    if (contentType === 21 && !this._recvKeys) {
      log.debug(`[TCP] Unencrypted TLS Alert from client: Level=${payload[0]}, Desc=${payload[1]}`);
      this._closeSocket(); return;
    }
    let innerType = contentType;
    let plainData = payload;
    if (this._recvKeys && contentType === 23) {
      const decrypted = this._decryptRecord(contentType, payload);
      if (!decrypted) return;
      innerType = decrypted.innerType;
      plainData = decrypted.plaintext;
    }
    if      (innerType === 22) this.tls.processHandshakeData(plainData);
    else if (innerType === 23) { if (this._handshakeDone) this.emit('data', plainData); else log.debug('[TCP] Application data before handshake'); }
    else if (innerType === 21) { log.debug(`[TCP] Encrypted TLS Alert from client: Level=${plainData[0]}, Desc=${plainData[1]}`); this._closeSocket(); }
  }

  _decryptRecord(contentType, ciphertext) {
    if (!this._recvKeys) return { plaintext: ciphertext, innerType: contentType };
    const { key, iv, cipher } = this._recvKeys;
    const nonce    = this._buildNonce(iv, this._seqRecv++);
    const tag      = ciphertext.subarray(ciphertext.length - 16);
    const body     = ciphertext.subarray(0, ciphertext.length - 16);
    const aad      = Buffer.from([0x17, 0x03, 0x03, 0x00, 0x00]);
    aad.writeUInt16BE(ciphertext.length, 3);
    const cipherFn = _tlsAeadAlgo(cipher);
    const dec      = crypto.createDecipheriv(cipherFn, key, nonce, { authTagLength: 16 });
    dec.setAAD(aad); dec.setAuthTag(tag);
    let plain;
    try { plain = Buffer.concat([dec.update(body), dec.final()]); }
    catch (e) { log.debug(`[TCP] Record decryption failed: ${e.message}`); return null; }
    let end = plain.length - 1;
    while (end >= 0 && plain[end] === 0) end--;
    if (end < 0) return null;
    return { innerType: plain[end], plaintext: plain.subarray(0, end) };
  }

  _plaintextRecord(contentType, data) {
    const header = Buffer.alloc(5);
    header[0] = contentType; header[1] = 0x03; header[2] = 0x03;
    header.writeUInt16BE(data.length, 3);
    return Buffer.concat([header, data]);
  }

  _startH2() {
    const { Http2Connection } = require('../connection/connection');
    const { H2Connection }    = require('../h2/http2');
    const sessionProxy = {
      write:          (buf) => this._writeRaw(this._encryptRecord(23, buf)),
      on:             (ev, fn) => this.on(ev, fn),
      once:           (ev, fn) => this.once(ev, fn),
      removeListener: (ev, fn) => this.removeListener(ev, fn),
      destroyed:      false,
      destroy:        () => this._closeSocket(),
    };
    this._h2FrameParser = new Http2Connection({ tlsSocket: sessionProxy, isServer: true }, this);
    this._h2 = new H2Connection(this, { isServer: true });
    this._h2.on('request', (req) => this.emit('request', req));
    this._h2.on('error',   (err) => this.emit('error', err));
    this._h2.on('end',     ()    => this.emit('end'));
  }

  sendHeaders(streamId, rawHeaderBlock, endStream) {
    if (this._h2FrameParser) this._h2FrameParser.sendHeaders(streamId, rawHeaderBlock, endStream);
  }
  sendData(streamId, data, endStream) {
    if (this._h2FrameParser) this._h2FrameParser._sendData(streamId, data, endStream);
  }
  close(errorCode) {
    if (this._h2FrameParser) this._h2FrameParser.close(errorCode);
    this._closeSocket();
  }
  _writeRaw(buf)  { if (!this._closed && this.socket.writable) this.socket.write(buf); }
  _closeSocket()  { if (this._closed) return; this._closed = true; if (this.socket && !this.socket.destroyed) this.socket.destroy(); }
  _cleanup()      { this._closed = true; this._h2 = null; this._h2FrameParser = null; }
}

class Server extends EventEmitter {
  constructor(options = {}) {
    super();
    this.port = options.port || 7844;
    this.host = options.host || '0.0.0.0';
    this.cert = options.cert || null;
    this.key  = options.key  || null;
    if (typeof this.cert === 'string' && !this.cert.includes('-----')) this.cert = fs.readFileSync(this.cert, 'utf8');
    if (typeof this.key  === 'string' && !this.key.includes('-----'))  this.key  = fs.readFileSync(this.key,  'utf8');
    if (this.cert && this.key) {
      const check = CertificateValidator.validateKeyMatch(this.cert, this.key);
      if (!check.valid) throw new Error(`Server cert/key mismatch: ${check.error}`);
      log.info('Certificate and private key validated successfully');
    }
    this.alpn         = options.alpn         || ['h3', 'h2', 'http/1.1'];
    this.cipherSuites = options.cipherSuites || undefined;
    this.requestCert        = options.requestCert        || false;
    this.rejectUnauthorized = options.rejectUnauthorized ?? false;
    this.ca                 = options.ca                 || null;
    this.transportParams    = options.transportParams    || {};
    this.keepaliveInterval  = options.keepaliveInterval  || 0;
    this.requireRetry = options.requireRetry || false;
    this.tokenKey     = crypto.randomBytes(16);
    this.supportedVersions = [QUIC_VERSION_1];
    this.ticketStore  = new SessionTicketStore();
    this.ticketKey    = options.ticketKey
      ? (Buffer.isBuffer(options.ticketKey) ? options.ticketKey : Buffer.from(options.ticketKey, 'hex'))
      : crypto.randomBytes(16);
    this.tcpServer   = null;
    this.udpSocket   = null;
    this.connections = new Map();
    this.stats = { packetsReceived: 0, packetsSent: 0, connectionsAccepted: 0 };
  }

  listen(port, host) {
    if (port !== undefined) this.port = port;
    if (host !== undefined) this.host = host;

    return new Promise((resolve, reject) => {
      this.tcpServer = net.createServer((socket) => {
        this.stats.connectionsAccepted++;
        const session = new TcpH2Session(socket, {
          cert:               this.cert,
          key:                this.key,
          alpn:               this.alpn.filter(a => a !== 'h3'),
          cipherSuites:       this.cipherSuites,
          requestCert:        this.requestCert,
          rejectUnauthorized: this.rejectUnauthorized,
          ca:                 this.ca,
        });

        session.on('request', (req) => {
          req.protocol = 'h2';
          const origRespond = req.respond.bind(req);
          req.respond = (status, headers = {}) => {
            headers['alt-svc'] = `h3=":${this.port}"; ma=86400, h3-29=":${this.port}"; ma=86400`;
            return origRespond(status, headers);
          };
          this.emit('request', req);
        });

        session.on('error', (err) => log.debug(`[TCP] Session error: ${err.message}`));
      });

      this.tcpServer.on('error', (err) => { this.emit('error', err); reject(err); });
      this.udpSocket = dgram.createSocket('udp4');
      this.udpSocket.on('message', (msg, rinfo) => { this.stats.packetsReceived++; this._handleDatagram(msg, rinfo); });
      this.udpSocket.on('error',   (err)         => { this.emit('error', err); reject(err); });

      this.udpSocket.bind(this.port, this.host, () => {
        const addr    = this.udpSocket.address();
        this.port     = addr.port;
        this.tcpServer.listen(this.port, this.host, () => {
          log.info(`Server listening on TCP & UDP ${addr.address}:${addr.port}`);
          this.emit('listening', addr);
          resolve(addr);
        });
      });
    });
  }

  _handleDatagram(buf, rinfo) {
    try {
      if (buf.length < 1) return;
      const isLong = (buf[0] & 0x80) !== 0;
      if (isLong) {
        const header = parsePacketHeader(buf);
        const conn   = this._findConnection(header.dcid);
        if (conn) { conn.remoteAddress = rinfo.address; conn.remotePort = rinfo.port; conn.receivePacket(buf); return; }
        if (header.packetType !== PACKET_TYPE.INITIAL) return;
        if (!this.supportedVersions.includes(header.version)) { this._sendRaw(buildVersionNegotiation(header.scid, header.dcid, this.supportedVersions), rinfo.address, rinfo.port); return; }
        if (buf.length < MIN_INITIAL_PACKET_SIZE) return;
        if (this.requireRetry && (!header.token || header.token.length === 0)) { this._sendRetry(header, rinfo); return; }
        if (header.token && header.token.length > 0) {
          const ok = validateToken(this.tokenKey, header.token, rinfo.address, rinfo.port, INITIAL_TOKEN_LIFETIME);
          if (!ok && this.requireRetry) { this._sendRetry(header, rinfo); return; }
        }
        this._acceptQuicConnection(buf, header, rinfo);
      } else {
        const conn = this._findConnectionByShortHeader(buf);
        if (conn) { conn.remoteAddress = rinfo.address; conn.remotePort = rinfo.port; conn.receivePacket(buf); }
      }
    } catch (err) { this.emit('error', err); }
  }

  _findConnectionByShortHeader(buf) { return buf.length < 9 ? null : this._findConnection(buf.subarray(1, 9)); }
  _findConnection(dcid)             { return !dcid ? null : (this.connections.get(dcid.toString('hex')) || null); }

  _acceptQuicConnection(buf, header, rinfo) {
    const serverCid = generateConnectionId(8);
    const transport = new Transport({
      transport: 'quic', isServer: true,
      scid: serverCid, dcid: header.scid, originalDcid: header.dcid,
      version: header.version, cert: this.cert, key: this.key,
      alpn: this.alpn, cipherSuites: this.cipherSuites,
      transportParams: this.transportParams, ticketStore: this.ticketStore,
      ticketKey: this.ticketKey, keepaliveInterval: this.keepaliveInterval,
      requestCert: this.requestCert, rejectUnauthorized: this.rejectUnauthorized,
      ca: this.ca,
      sendDatagram: (data, addr, port) => this._sendRaw(data, addr, port),
      remoteAddress: rinfo.address, remotePort: rinfo.port,
    });

    this.connections.set(serverCid.toString('hex'), transport);
    this.connections.set(header.dcid.toString('hex'), transport);
    transport._impl._acceptInitial(header.dcid, header.scid);

    transport.on('connected', () => {
      this.stats.connectionsAccepted++;
      log.info(`[QUIC] Connection established from ${rinfo.address}:${rinfo.port}`);

      const h3 = new H3Connection(transport, {
        isServer:           true,
        enableWebTransport: this.transportParams.enableWebTransport || true,
      });

      h3.on('request', (req) => {
        req.protocol = 'h3';

        if (!req.socket) {
            req.socket = {
                remoteAddress: rinfo.address,
                remotePort: rinfo.port
            };
        }

        if (!req.rawHeaders) {
          req.rawHeaders = Object.entries(req.headers || {}).flat();
        }

        this.emit('request', req);
      });

      this.emit('connection', transport);
    });

    transport.on('closed',  ()    => { this.connections.delete(serverCid.toString('hex')); this.connections.delete(header.dcid.toString('hex')); });
    transport.on('error',   (err) => this.emit('connectionError', err, transport));
    transport.receivePacket(buf);
  }

  _sendRetry(header, rinfo) {
    const newScid = generateConnectionId(8);
    const token   = generateToken(this.tokenKey, header.dcid, rinfo.address, rinfo.port);
    const parts   = [Buffer.from([(0xc0 | (PACKET_TYPE.RETRY << 4) | 0x0f)])];
    const vBuf    = Buffer.alloc(4); vBuf.writeUInt32BE(header.version, 0); parts.push(vBuf);
    parts.push(Buffer.from([header.scid.length]), header.scid);
    parts.push(Buffer.from([newScid.length]),     newScid);
    parts.push(token);
    const withoutTag   = Buffer.concat(parts);
    const integrityTag = computeRetryIntegrityTag(header.version, header.dcid, withoutTag);
    this._sendRaw(Buffer.concat([withoutTag, integrityTag]), rinfo.address, rinfo.port);
  }

  _sendRaw(data, address, port) {
    if (!this.udpSocket) return;
    this.stats.packetsSent++;
    this.udpSocket.send(data, 0, data.length, port, address, (err) => { if (err) this.emit('error', err); });
  }

  close() {
    return new Promise((resolve) => {
      for (const [, conn] of this.connections) conn.close();
      Promise.all([
        this.udpSocket ? new Promise(r => this.udpSocket.close(r)) : Promise.resolve(),
        this.tcpServer ? new Promise(r => this.tcpServer.close(r)) : Promise.resolve(),
      ]).then(() => { this.emit('close'); resolve(); });
    });
  }
}

module.exports = { Server };