'use strict';

/**
 * HTTP/2-over-TCP outbound (dialing) client.
 *
 * server.js has a full server-side TLS-record layer (TcpH2Session) that wraps
 * a net.Socket with this project's own zero-dependency TLS 1.3 engine, but it
 * is hardcoded isServer:true. There was no client-side counterpart anywhere,
 * so the HTTP/2 fallback path (used while a QUIC/H3 connection hasn't been
 * established, or a host doesn't advertise Alt-Svc h3 at all) never actually
 * worked from this library. TcpH2ClientSession mirrors TcpH2Session's record
 * layer for the outbound/client role and drives the handshake explicitly
 * (generateClientHello() -> write plaintext record -> feed replies back in).
 */

const net    = require('net');
const crypto = require('crypto');
const { EventEmitter } = require('events');

const { TLS } = require('../crypto/tls');
const { createLogger } = require('../utils/logger');
const { collectResponse } = require('./response');

const log = createLogger('Http2Client');

// Same fix as server.js's TcpH2Session: don't silently map a negotiated
// chacha20-poly1305 suite onto aes-128-gcm (wrong algorithm, wrong key
// length, guaranteed to throw or produce garbage).
function tlsAeadAlgo(cipherName) {
  if (cipherName === 'chacha20-poly1305') return 'chacha20-poly1305';
  return cipherName && cipherName.includes('256') ? 'aes-256-gcm' : 'aes-128-gcm';
}

class TcpH2ClientSession extends EventEmitter {
  constructor(socket, tlsOpts = {}) {
    super();
    this.socket  = socket;
    this._closed = false;

    this.tls = new TLS({
      transport:          'tcp',
      isServer:            false,
      serverName:          tlsOpts.serverName,
      alpn:                tlsOpts.alpn || ['h2', 'http/1.1'],
      cipherSuites:        tlsOpts.cipherSuites,
      rejectUnauthorized:  tlsOpts.rejectUnauthorized !== undefined ? tlsOpts.rejectUnauthorized : true,
      ca:                  tlsOpts.ca || null,
      clientCert:          tlsOpts.clientCert || null,
      clientKey:           tlsOpts.clientKey || null,
      sessionTicket:       tlsOpts.sessionTicket || null,
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
      this.emit('secure', info);
    };

    this.tls.onError = (err) => {
      this.emit('error', err);
      this._closeSocket();
    };
  }

  _wireSocket() {
    this.socket.on('connect', () => this._startHandshake());
    this.socket.on('data',  (chunk) => this._onRawData(chunk));
    this.socket.on('end',   ()      => { if (this._h2) this._h2.emit('end'); else this.emit('end'); });
    this.socket.on('error', (err)   => { if (this._h2) this._h2.emit('error', err); else this.emit('error', err); });
    this.socket.on('close', ()      => this._cleanup());
  }

  _startHandshake() {
    const { data } = this.tls.generateClientHello();
    this._writeRaw(this._plaintextRecord(22, data));
    // TLS 1.3 middlebox-compatibility change_cipher_spec (RFC 8446 D.4) - most
    // servers ignore it, some middleboxes require seeing it.
    this._writeRaw(Buffer.from([0x14, 0x03, 0x03, 0x00, 0x01, 0x01]));
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
    const cipherFn = tlsAeadAlgo(cipher);
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
      log.debug(`[TCP] Unencrypted TLS alert from server: level=${payload[0]}, desc=${payload[1]}`);
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
    else if (innerType === 21) { log.debug(`[TCP] Encrypted TLS alert from server: level=${plainData[0]}, desc=${plainData[1]}`); this._closeSocket(); }
  }

  _decryptRecord(contentType, ciphertext) {
    if (!this._recvKeys) return { plaintext: ciphertext, innerType: contentType };
    const { key, iv, cipher } = this._recvKeys;
    const nonce    = this._buildNonce(iv, this._seqRecv++);
    const tag      = ciphertext.subarray(ciphertext.length - 16);
    const body     = ciphertext.subarray(0, ciphertext.length - 16);
    const aad      = Buffer.from([0x17, 0x03, 0x03, 0x00, 0x00]);
    aad.writeUInt16BE(ciphertext.length, 3);
    const cipherFn = tlsAeadAlgo(cipher);
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

  startH2() {
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
    this._h2FrameParser = new Http2Connection({ tlsSocket: sessionProxy, isServer: false }, this);
    this._h2 = new H2Connection(this, { isServer: false });
    return this._h2;
  }

  // H2Connection.request() (client role) calls this.tcp.createStream() to
  // originate a new request stream - the server role never does (it only
  // reacts to incoming HEADERS frames), which is why this was missing here:
  // server.js's TcpH2Session never needed it either.
  createStream(bidirectional = true) {
    if (!this._h2FrameParser) throw new Error('createStream() called before ALPN=h2 was negotiated');
    return this._h2FrameParser.createStream(bidirectional);
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
  _cleanup()      { this._closed = true; this._h2 = null; this._h2FrameParser = null; this.emit('close'); }
}

/**
 * Dial host:port over TCP+TLS1.3 and negotiate HTTP/2 via ALPN.
 * Resolves with { session, h2, close(code) }.
 */
function connectHttp2(host, port = 443, options = {}) {
  const timeoutMs = options.timeout || 8000;

  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    const session = new TcpH2ClientSession(socket, {
      serverName:         host,
      alpn:               options.alpn || ['h2', 'http/1.1'],
      cipherSuites:       options.cipherSuites,
      rejectUnauthorized: options.rejectUnauthorized,
      ca:                 options.ca || null,
      clientCert:         options.clientCert || null,
      clientKey:          options.clientKey || null,
      sessionTicket:      options.sessionTicket || null,
    });

    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(new Error(`HTTP/2 (TCP+TLS) handshake to ${host}:${port} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    if (typeof timer.unref === 'function') timer.unref();

    socket.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });

    session.once('secure', (info) => {
      if (settled) return;
      if (info.alpn !== 'h2') {
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        reject(new Error(`Server did not negotiate HTTP/2 over ALPN (got '${info.alpn || 'none'}')`));
        return;
      }
      settled = true;
      clearTimeout(timer);
      const h2 = session.startH2();
      resolve({
        session,
        h2,
        // Convenience wrapper around h2.request(), matching quic-client's
        // and HttpClient's shape.
        fetch: (method, path, headers = {}, reqOptions = {}) => {
          const req = h2.request(method, path, headers, { authority: host, endStream: true, ...reqOptions });
          return collectResponse(req, 'h2');
        },
        close: (code) => session.close(code),
      });
    });

    session.once('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
  });
}

module.exports = { TcpH2ClientSession, connectHttp2 };
