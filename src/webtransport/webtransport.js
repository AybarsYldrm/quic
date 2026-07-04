'use strict';

/**
 * WebTransport over HTTP/3
 *
 * Implements WebTransport protocol per:
 * - RFC 9220 (Extended CONNECT)
 * - draft-ietf-webtrans-http3 (WebTransport over HTTP/3)
 *
 * Features:
 * - Session establishment via CONNECT :protocol=webtransport
 * - Bidirectional streams
 * - Unidirectional streams
 * - Datagram support (RFC 9297)
 * - Chrome-compatible behavior
 *
 * Server usage:
 *   const wt = new WebTransportServer(h3conn, quicConn);
 *   wt.on('session', (session) => {
 *     session.on('bidiStream', (stream) => { ... });
 *     session.on('datagram', (data) => { ... });
 *   });
 *
 * Client usage:
 *   const session = await WebTransportClient.connect(url, h3conn);
 *   const stream = session.createBidiStream();
 */

const { EventEmitter } = require('events');
const crypto = require('crypto');
const { encodeVarInt } = require('../transport/varint');
const { createLogger } = require('../utils/logger');

const log = createLogger('WebTransport');

// Resume-token format: base64url( payload || HMAC-SHA256(secret, payload)[0..15] )
// payload = JSON({ v:1, sid, url, exp, ctx })
const RESUME_TOKEN_VERSION = 1;
const RESUME_TOKEN_DEFAULT_TTL_MS = 10 * 60 * 1000;
const RESUME_TOKEN_TAG_LEN = 16;

// WebTransport session states
const WT_STATE = {
  CONNECTING: 'connecting',
  CONNECTED:  'connected',
  CLOSING:    'closing',
  CLOSED:     'closed',
};

/**
 * WebTransport Session
 * Represents a single WebTransport session over an HTTP/3 connection.
 */
class WebTransportSession extends EventEmitter {
  constructor(options = {}) {
    super();

    // Session ID is the stream ID of the CONNECT request (RFC 9220 / draft-07).
    this.id = options.sessionId || 0;
    this.state = WT_STATE.CONNECTING;
    this.h3Request = options.h3Request || null;
    this.h3Conn = options.h3Conn || null;
    this.quicConn = options.quicConn || null;
    this.stream = options.stream || null;
    this.url = options.url || '';

    // Streams associated with this session
    this.bidiStreams = new Map();
    this.uniStreams = new Map();
    this.nextBidiStreamId = 0;
    this.nextUniStreamId = 0;
  }

  /**
   * Dispatch an inbound WT bidi stream (already stripped of 0x41 + session_id prefix).
   */
  _acceptBidiStream(stream, seedPayload) {
    this.bidiStreams.set(stream.id, stream);
    stream.on('end', () => this.bidiStreams.delete(stream.id));
    // Replay any seed payload that was carried in the first chunk.
    if (seedPayload && seedPayload.length > 0) {
      queueMicrotask(() => stream.emit('data', seedPayload));
    }
    this.emit('bidiStream', stream);
  }

  /**
   * Dispatch an inbound WT uni stream (already stripped of 0x54 + session_id prefix).
   */
  _acceptUniStream(stream, seedPayload) {
    this.uniStreams.set(stream.id, stream);
    stream.on('end', () => this.uniStreams.delete(stream.id));
    if (seedPayload && seedPayload.length > 0) {
      queueMicrotask(() => stream.emit('data', seedPayload));
    }
    this.emit('uniStream', stream);
  }

  /**
   * Dispatch an inbound H3 datagram (already stripped of quarter-stream-id prefix).
   */
  _deliverDatagram(payload) {
    this.emit('datagram', payload);
  }

  /**
   * Accept the session (server-side)
   */
  accept(headers = {}) {
    if (this.state !== WT_STATE.CONNECTING) return;

    const responseHeaders = {
      'sec-webtransport-http3-draft': 'draft02',
      'sec-webtransport-http3-draft02': '?1',
      'capsule-protocol': '?1',
      ...headers,
    };

    if (this.h3Request) {
      this.h3Request.respond(200, responseHeaders);
    }

    this.state = WT_STATE.CONNECTED;
    log.info(`WebTransport session ${this.id} accepted`);
    this.emit('connected');
  }

  /**
   * Reject the session (server-side)
   */
  reject(statusCode = 403, reason = 'Rejected') {
    if (this.state !== WT_STATE.CONNECTING) return;

    if (this.h3Request) {
      this.h3Request.respond(statusCode, {}).end(reason);
    }

    this.state = WT_STATE.CLOSED;
    this.emit('closed', { code: statusCode, reason });
  }

  /**
   * Create a bidirectional stream.
   * Per draft-ietf-webtrans-http3-07 §4.2, a WT bidi stream starts with
   * varint(WT_BIDI_STREAM_HEADER=0x41) || varint(session_id).
   */
  createBidiStream() {
    if (this.state !== WT_STATE.CONNECTED) throw new Error('Session not connected');
    if (!this.quicConn) throw new Error('No QUIC connection');

    const stream = this.quicConn.createStream(true);
    stream.write(Buffer.concat([encodeVarInt(0x41), encodeVarInt(this.id)]));
    this.bidiStreams.set(stream.id, stream);
    stream.on('end', () => this.bidiStreams.delete(stream.id));
    log.debug(`Created bidi stream ${stream.id} for session ${this.id}`);
    return stream;
  }

  /**
   * Create a unidirectional stream.
   * Per draft §4.2: varint(WT_UNI_STREAM_TYPE=0x54) || varint(session_id).
   */
  createUniStream() {
    if (this.state !== WT_STATE.CONNECTED) throw new Error('Session not connected');
    if (!this.quicConn) throw new Error('No QUIC connection');

    const stream = this.quicConn.createStream(false);
    stream.write(Buffer.concat([encodeVarInt(0x54), encodeVarInt(this.id)]));
    this.uniStreams.set(stream.id, stream);
    stream.on('end', () => this.uniStreams.delete(stream.id));
    log.debug(`Created uni stream ${stream.id} for session ${this.id}`);
    return stream;
  }

  /**
   * Send datagram (unreliable, unordered) scoped to this session via RFC 9297.
   */
  sendDatagram(data) {
    if (this.state !== WT_STATE.CONNECTED) return false;
    if (!this.h3Conn) return false;
    return this.h3Conn.sendH3Datagram(this.id, data);
  }

  /**
   * Close the session
   */
  close(code = 0, reason = '') {
    if (this.state === WT_STATE.CLOSED) return;
    this.state = WT_STATE.CLOSING;

    // Close all streams
    for (const [, stream] of this.bidiStreams) {
      try { stream.end(); } catch (_) {}
    }
    for (const [, stream] of this.uniStreams) {
      try { stream.end(); } catch (_) {}
    }

    // Close the control stream (the original CONNECT request stream)
    if (this.stream) {
      try { this.stream.end(); } catch (_) {}
    }

    this.state = WT_STATE.CLOSED;
    this.emit('closed', { code, reason });
    log.info(`WebTransport session ${this.id} closed`);
  }

  /**
   * Get session statistics
   */
  get stats() {
    return {
      sessionId: this.id,
      state: this.state,
      bidiStreams: this.bidiStreams.size,
      uniStreams: this.uniStreams.size,
      url: this.url,
    };
  }
}

/**
 * WebTransport Server Handler
 * Manages WebTransport sessions on the server side.
 */
class WebTransportServer extends EventEmitter {
  constructor(options = {}) {
    super();
    this.sessions = new Map();               // sessionId (= stream id) -> session
    this._boundH3Conns = new WeakSet();       // ensure per-conn router installed once
    this.maxSessions = options.maxSessions || 100;

    // Resume tokens: HMAC-signed opaque blobs that attest a prior session.
    // Server secret rotates per process unless caller supplies one.
    this._resumeSecret = options.resumeSecret
      ? Buffer.from(options.resumeSecret)
      : crypto.randomBytes(32);
    this._resumeTokenTtlMs = options.resumeTokenTtlMs || RESUME_TOKEN_DEFAULT_TTL_MS;
  }

  /**
   * Issue a resume token for the given session. Token is opaque base64url
   * carrying { sessionId, url, expiresAt, ctx }, integrity-protected by
   * HMAC-SHA256 over the server's resume secret. The token is meaningful
   * only to this process (or to a cluster sharing `resumeSecret`).
   *
   * @param {WebTransportSession} session
   * @param {object} [ctx] optional opaque application context (must be JSON-safe)
   * @returns {string} base64url-encoded token
   */
  issueResumeToken(session, ctx = null) {
    if (!session) throw new Error('issueResumeToken: session required');
    const payload = {
      v:   RESUME_TOKEN_VERSION,
      sid: session.id,
      url: session.url || '',
      exp: Date.now() + this._resumeTokenTtlMs,
      ctx: ctx == null ? null : ctx,
    };
    const payloadBuf = Buffer.from(JSON.stringify(payload), 'utf8');
    const tag = crypto
      .createHmac('sha256', this._resumeSecret)
      .update(payloadBuf)
      .digest()
      .subarray(0, RESUME_TOKEN_TAG_LEN);
    return Buffer.concat([payloadBuf, tag]).toString('base64url');
  }

  /**
   * Verify a resume token. Returns the parsed payload on success, or null
   * if the token is malformed, expired, or fails HMAC verification.
   * @param {string} token
   * @returns {{v:number,sid:number,url:string,exp:number,ctx:any}|null}
   */
  verifyResumeToken(token) {
    if (typeof token !== 'string' || token.length === 0) return null;
    let buf;
    try { buf = Buffer.from(token, 'base64url'); } catch (_) { return null; }
    if (buf.length <= RESUME_TOKEN_TAG_LEN) return null;
    const payloadBuf = buf.subarray(0, buf.length - RESUME_TOKEN_TAG_LEN);
    const givenTag   = buf.subarray(buf.length - RESUME_TOKEN_TAG_LEN);
    const expectTag  = crypto
      .createHmac('sha256', this._resumeSecret)
      .update(payloadBuf)
      .digest()
      .subarray(0, RESUME_TOKEN_TAG_LEN);
    if (givenTag.length !== expectTag.length) return null;
    if (!crypto.timingSafeEqual(givenTag, expectTag)) return null;
    let payload;
    try { payload = JSON.parse(payloadBuf.toString('utf8')); } catch (_) { return null; }
    if (!payload || payload.v !== RESUME_TOKEN_VERSION) return null;
    if (typeof payload.exp !== 'number' || payload.exp <= Date.now()) return null;
    return payload;
  }

  /**
   * Check if an H3 request is a WebTransport CONNECT
   */
  static isWebTransportRequest(h3req) {
    const method = (h3req.method || '').toUpperCase();
    const protocol = h3req.headers && h3req.headers[':protocol'];
    return method === 'CONNECT' && protocol === 'webtransport';
  }

  /**
   * Install per-session stream/datagram routers on an H3Connection exactly once.
   */
  _bindH3Conn(h3Conn) {
    if (!h3Conn || this._boundH3Conns.has(h3Conn)) return;
    this._boundH3Conns.add(h3Conn);

    h3Conn.on('wtBidiStream', (sessionId, stream, seed) => {
      const session = this.sessions.get(sessionId);
      if (session) session._acceptBidiStream(stream, seed);
      else log.trace(`WT bidi stream for unknown session ${sessionId}; dropping`);
    });
    h3Conn.on('wtUniStream', (sessionId, stream, seed) => {
      const session = this.sessions.get(sessionId);
      if (session) session._acceptUniStream(stream, seed);
      else log.trace(`WT uni stream for unknown session ${sessionId}; dropping`);
    });
    h3Conn.on('h3datagram', (sessionId, payload) => {
      const session = this.sessions.get(sessionId);
      if (session) session._deliverDatagram(payload);
    });
  }

  /**
   * Handle a WebTransport CONNECT request.
   * Returns a WebTransportSession that can be accepted or rejected.
   * @param {H3Request} h3req
   * @param {H3Connection} h3Conn
   * @param {QuicConnection} quicConn
   */
  handleConnect(h3req, h3Conn, quicConn) {
    if (this.sessions.size >= this.maxSessions) {
      log.warn('Maximum WebTransport sessions reached');
      h3req.respond(503, {}).end('Too many sessions');
      return null;
    }

    this._bindH3Conn(h3Conn);

    // Session id MUST be the CONNECT request stream id (draft-07 §2).
    const sessionId = h3req.stream ? h3req.stream.id : 0;
    const session = new WebTransportSession({
      sessionId,
      h3Request: h3req,
      h3Conn,
      quicConn,
      stream: h3req.stream,
      url: h3req.path || '/',
    });

    this.sessions.set(sessionId, session);

    session.on('closed', () => {
      this.sessions.delete(sessionId);
      log.debug(`Session ${sessionId} removed. Active: ${this.sessions.size}`);
    });

    log.info(`WebTransport session ${sessionId} created for ${h3req.path}`);
    this.emit('session', session);
    return session;
  }

  /**
   * Close all sessions
   */
  closeAll() {
    for (const [, session] of this.sessions) {
      session.close();
    }
    this.sessions.clear();
  }
}

/**
 * WebTransport Client
 * Establishes a WebTransport session from the client side.
 */
class WebTransportClient {
  /**
   * Connect to a WebTransport server
   * @param {string} url - WebTransport URL (e.g., https://example.com/wt)
   * @param {H3Connection} h3conn - Established HTTP/3 connection
   * @param {QuicConnection} quicConn - QUIC connection
   * @returns {Promise<WebTransportSession>}
   */
  static connect(url, h3conn, quicConn, options = {}) {
    return new Promise((resolve, reject) => {
      const timeout = options.timeout || 10000;
      const parsedUrl = new URL(url);
      const path = parsedUrl.pathname + parsedUrl.search;

      const timer = setTimeout(() => {
        reject(new Error('WebTransport connect timeout'));
      }, timeout);

      const req = h3conn.request('CONNECT', path, {
        ':protocol': 'webtransport',
        'sec-webtransport-http3-draft': 'draft02',
        'origin': parsedUrl.origin,
      }, {
        authority: parsedUrl.host,
        scheme: 'https',
      });

      req.on('headers', (headers) => {
        clearTimeout(timer);

        if (req.status === 200) {
          const sessionId = req.stream ? req.stream.id : 0;
          const session = new WebTransportSession({
            sessionId,
            h3Request: req,
            h3Conn: h3conn,
            quicConn,
            stream: req.stream,
            url,
          });
          // Route inbound WT streams + datagrams on this h3 connection to sessions.
          if (!h3conn._wtClientRouter) {
            h3conn._wtClientRouter = new Map();
            h3conn.on('wtBidiStream', (sid, s, seed) => {
              const sess = h3conn._wtClientRouter.get(sid);
              if (sess) sess._acceptBidiStream(s, seed);
            });
            h3conn.on('wtUniStream', (sid, s, seed) => {
              const sess = h3conn._wtClientRouter.get(sid);
              if (sess) sess._acceptUniStream(s, seed);
            });
            h3conn.on('h3datagram', (sid, payload) => {
              const sess = h3conn._wtClientRouter.get(sid);
              if (sess) sess._deliverDatagram(payload);
            });
          }
          h3conn._wtClientRouter.set(sessionId, session);
          session.state = WT_STATE.CONNECTED;
          resolve(session);
        } else {
          reject(new Error(`WebTransport rejected with status ${req.status}`));
        }
      });

      req.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });

      // Don't end the request stream - it stays open for the session
    });
  }
}

module.exports = {
  WebTransportSession,
  WebTransportServer,
  WebTransportClient,
  WT_STATE,
};
