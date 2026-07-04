'use strict';

/**
 * Unified HTTP client: races HTTP/3 (QUIC) against HTTP/2 (TCP+TLS) for the
 * first request to an origin, and remembers which protocol won (or what an
 * Alt-Svc response header advertised) so later requests to the same origin
 * go straight to QUIC.
 *
 * This exists because, previously, there was no client-side connection
 * orchestration at all in this library - only a server that accepts inbound
 * H2/H3 connections. The user-visible symptom of that gap was exactly the
 * "alt-svc'den h3'e gecis gecikmesi" complaint: without this, the only way
 * to get to HTTP/3 would have been to serially connect over TCP first, read
 * an Alt-Svc header, then open a *second* connection over QUIC - paying a
 * full extra handshake's worth of latency on every cold connection. Racing
 * the two dials in parallel (a QUIC/TCP "happy eyeballs" for HTTP) removes
 * that serial penalty, and the Alt-Svc/h3 cache means it only ever happens
 * once per origin.
 */

const { connectQuic }  = require('./quic-client');
const { connectHttp2 } = require('./http2-client');
const { collectResponse } = require('./response');
const { createLogger } = require('../utils/logger');

const log = createLogger('HttpClient');

const DEFAULT_ALT_SVC_MAX_AGE = 86400;

function parseAltSvc(headerValue) {
  if (!headerValue) return null;
  for (const entry of String(headerValue).split(',')) {
    const m = entry.match(/h3(?:-\d+)?=":(\d+)"/);
    if (!m) continue;
    const maMatch = entry.match(/ma=(\d+)/);
    return {
      port:   parseInt(m[1], 10),
      maxAge: maMatch ? parseInt(maMatch[1], 10) : DEFAULT_ALT_SVC_MAX_AGE,
    };
  }
  return null;
}

class AltSvcCache {
  constructor() { this._map = new Map(); }
  get(origin) {
    const entry = this._map.get(origin);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) { this._map.delete(origin); return null; }
    return entry;
  }
  set(origin, port, maxAgeSeconds) {
    this._map.set(origin, { port, expiresAt: Date.now() + maxAgeSeconds * 1000 });
  }
}

class HttpClient {
  constructor(options = {}) {
    this.defaultOptions = options;
    this.altSvc      = new AltSvcCache();
    this._h3Conns     = new Map(); // origin -> Promise<{transport,h3}>
    this._h2Conns     = new Map(); // origin -> Promise<{session,h2}>
  }

  _origin(host, port) { return `${host}:${port}`; }

  _getH3(host, port, options) {
    const origin = this._origin(host, port);
    let p = this._h3Conns.get(origin);
    if (p) return p;
    p = connectQuic(host, port, { ...this.defaultOptions, ...options }).then((entry) => {
      entry.transport.on('closed', () => this._h3Conns.delete(origin));
      return entry;
    });
    p.catch(() => this._h3Conns.delete(origin));
    this._h3Conns.set(origin, p);
    return p;
  }

  _getH2(host, port, options) {
    const origin = this._origin(host, port);
    let p = this._h2Conns.get(origin);
    if (p) return p;
    p = connectHttp2(host, port, { ...this.defaultOptions, ...options }).then((entry) => {
      entry.session.once('close', () => this._h2Conns.delete(origin));
      entry.session.socket.once('close', () => this._h2Conns.delete(origin));
      return entry;
    });
    p.catch(() => this._h2Conns.delete(origin));
    this._h2Conns.set(origin, p);
    return p;
  }

  _learnAltSvc(host, port, headers) {
    const parsed = parseAltSvc(headers && headers['alt-svc']);
    if (!parsed) return;
    const origin = this._origin(host, port);
    this.altSvc.set(origin, parsed.port, parsed.maxAge);
    log.info(`[HttpClient] ${origin} advertises h3 on port ${parsed.port} (cached ${parsed.maxAge}s)`);
  }

  async _requestViaH3(host, port, path, method, headers, options) {
    const { h3 } = await this._getH3(host, port, options);
    const req = h3.request(method, path, headers, { authority: host, endStream: true });
    const res = await collectResponse(req, 'h3');
    this._learnAltSvc(host, port, res.headers);
    return res;
  }

  async _requestViaH2(host, port, path, method, headers, options) {
    const { h2 } = await this._getH2(host, port, options);
    const req = h2.request(method, path, headers, { authority: host, endStream: true });
    const res = await collectResponse(req, 'h2');
    this._learnAltSvc(host, port, res.headers);
    return res;
  }

  _raceH2AndH3(host, port, path, method, headers, options) {
    return new Promise((resolve, reject) => {
      let pending = 2;
      let firstError = null;
      const onOutcome = (ok, value) => {
        pending--;
        if (ok) { resolve(value); return; }
        if (!firstError) firstError = value;
        if (pending === 0) reject(firstError);
      };
      this._requestViaH3(host, port, path, method, headers, options)
        .then((res) => onOutcome(true, res), (err) => onOutcome(false, err));
      this._requestViaH2(host, port, path, method, headers, options)
        .then((res) => onOutcome(true, res), (err) => onOutcome(false, err));
    });
  }

  /**
   * request(url, { method, headers, timeout, rejectUnauthorized, ca, ... })
   * -> { status, headers, body, protocol }
   */
  async request(urlString, options = {}) {
    const url    = new URL(urlString);
    const host   = url.hostname;
    const port   = Number(url.port) || 443;
    const path   = url.pathname + url.search || '/';
    const method = options.method || 'GET';
    const headers = options.headers || {};
    const origin = this._origin(host, port);

    const cached = this.altSvc.get(origin);
    if (cached) {
      try {
        return await this._requestViaH3(host, cached.port, path, method, headers, options);
      } catch (e) {
        log.warn(`[HttpClient] cached h3 route for ${origin} failed (${e.message}); falling back to h2`);
        this.altSvc._map.delete(origin);
      }
    }

    if (options.protocol === 'h3') return this._requestViaH3(host, port, path, method, headers, options);
    if (options.protocol === 'h2') return this._requestViaH2(host, port, path, method, headers, options);

    return this._raceH2AndH3(host, port, path, method, headers, options);
  }

  async close() {
    const closers = [];
    for (const p of this._h3Conns.values()) closers.push(p.then((e) => e.close()).catch(() => {}));
    for (const p of this._h2Conns.values()) closers.push(p.then((e) => e.session.close()).catch(() => {}));
    this._h3Conns.clear();
    this._h2Conns.clear();
    await Promise.all(closers);
  }
}

module.exports = { HttpClient, AltSvcCache, parseAltSvc };
