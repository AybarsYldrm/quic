'use strict';

const { createLogger } = require('../utils/logger');
// KRİTİK EKLENTİ: Yazdığın 0-RTT güvenlik modülünü içeri alıyoruz
const { composePolicy, ReplayCache } = require('../crypto/early-data-policy'); 

const log = createLogger('Router');

// Global 0-RTT Security Policy (RAM'de tek kopya, state tutar)
const replayCache = new ReplayCache({ ttlMs: 10000, maxSize: 5000 });
const earlyDataPolicy = composePolicy({
  requireSafe: true,
  replayCache: replayCache
});

class Router {
  constructor(options = {}) {
    this.routes = [];
    this.middleware = [];
    this.altSvcPort = options.altSvcPort || 443;
    this.cors = options.cors !== false ? {
      origin: (options.cors && options.cors.origin) || '*',
      methods: (options.cors && options.cors.methods) || 'GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS',
      headers: (options.cors && options.cors.headers) || 'Content-Type, Authorization, Cookie, X-Requested-With',
      maxAge:  (options.cors && options.cors.maxAge)  || 86400,
    } : null;
  }

  use(pathOrFn, fn) {
    if (typeof pathOrFn === 'function') {
      this.middleware.push({ path: null, handler: pathOrFn });
    } else {
      this.middleware.push({ path: pathOrFn, handler: fn });
    }
    return this;
  }

  get(path, ...handlers)     { return this._addRoute('GET', path, handlers); }
  post(path, ...handlers)    { return this._addRoute('POST', path, handlers); }
  put(path, ...handlers)     { return this._addRoute('PUT', path, handlers); }
  delete(path, ...handlers)  { return this._addRoute('DELETE', path, handlers); }
  patch(path, ...handlers)   { return this._addRoute('PATCH', path, handlers); }
  options(path, ...handlers) { return this._addRoute('OPTIONS', path, handlers); }
  head(path, ...handlers)    { return this._addRoute('HEAD', path, handlers); }
  all(path, ...handlers)     { return this._addRoute('*', path, handlers); }

  _addRoute(method, path, handlers) {
    const { regex, paramNames } = compilePath(path);
    this.routes.push({ method, path, regex, paramNames, handlers });
    return this;
  }

  handle(h3req, quicConn) {
    const method = (h3req.method || 'GET').toUpperCase();
    const rawPath = h3req.path || '/';
    const qIdx = rawPath.indexOf('?');
    
    // Query string (?) ayrıştırması
    const pathname = qIdx >= 0 ? rawPath.slice(0, qIdx) : rawPath;
    const queryString = qIdx >= 0 ? rawPath.slice(qIdx + 1) : '';

    const req = new RouterRequest(h3req, { method, pathname, queryString, quicConn });
    const res = new RouterResponse(h3req);

    // ==============================================================
    // CORE SECURITY: 0-RTT (EARLY DATA) REPLAY ATTACK SHIELD
    // ==============================================================
    if (quicConn && req.raw && req.raw.stream) {
      if (quicConn.is0RTT && quicConn.is0RTT(req.raw.stream.id)) {
        
        // Real ticket-bound nonce from the TLS engine. If the connection
        // has no ticket nonce we skip replay keying — the method/body
        // safety check in composePolicy still applies.
        const ticketNonce = typeof quicConn.get0RTTNonce === 'function'
          ? quicConn.get0RTTNonce()
          : null;

        const ctx = ticketNonce ? { ticketNonce } : {};
        const policyResult = earlyDataPolicy(req, ctx);

        if (policyResult.accept) {
          // Politikadan geçti: Güvenli metod, body yok, replay değil.
          res.set('Early-Data', '1');
        } else {
          // Politikaya takıldı! Zinciri kes ve 425 dön.
          log.warn(`[SECURITY] 0-RTT engellendi! Sebep: ${policyResult.reason}, Path: ${pathname}`);
          res.status(425).json({ 
            status: 'error', 
            message: 'Too Early. Request not allowed in 0-RTT or replay detected.',
            reason: policyResult.reason
          });
          return; // İşlemi burada bitir
        }
      }
    }

    // ==============================================================
    // PRODUCTION DEFAULTS: Alt-Svc broadcast + CORS preflight
    // ==============================================================
    if (!res._headers['alt-svc']) {
      res.set('alt-svc', `h3=":${this.altSvcPort}"; ma=86400`);
    }
    if (this.cors && !res._headers['access-control-allow-origin']) {
      res.set('access-control-allow-origin', this.cors.origin);
      res.set('vary', 'Origin');
    }

    // Routes that the application registered explicitly still win; only
    // short-circuit OPTIONS when no route handler declared it.
    if (method === 'OPTIONS' && this.cors) {
      let explicit = false;
      for (const route of this.routes) {
        if (route.method !== 'OPTIONS' && route.method !== '*') continue;
        if (route.regex.test(pathname)) { explicit = true; break; }
      }
      if (!explicit) {
        res.set('access-control-allow-methods', this.cors.methods);
        res.set('access-control-allow-headers',
          req.headers['access-control-request-headers'] || this.cors.headers);
        res.set('access-control-max-age', String(this.cors.maxAge));
        res.set('content-length', '0');
        res._headersSent = true;
        h3req.respond(204, res._headers).end();
        return;
      }
    }

    const allHandlers = [];

    // 1. Eşleşen Middleware'leri Topla
    for (const mw of this.middleware) {
      if (!mw.path || pathname.startsWith(mw.path)) {
        allHandlers.push(mw.handler);
      }
    }

    // 2. Eşleşen Rotayı Bul
    for (const route of this.routes) {
      if (route.method !== '*' && route.method !== method) continue;
      const match = route.regex.exec(pathname);
      if (match) {
        const params = {};
        for (let i = 0; i < route.paramNames.length; i++) {
          params[route.paramNames[i]] = decodeURIComponent(match[i + 1]);
        }
        req.params = params;
        for (const h of route.handlers) {
          allHandlers.push(h);
        }
        break; // İlk eşleşen rotada dur
      }
    }

    // 3. Zinciri (Chain) Çalıştır
    let idx = 0;
    const next = (err) => {
      if (err) {
        log.error('Route handler error:', err.message || err);
        if (!res._headersSent) {
          res.status(500).json({ error: 'Internal Server Error' });
        }
        return;
      }

      // 404 KONTROLÜ
      if (idx >= allHandlers.length) {
        if (!res._headersSent) {
          res.status(404).json({ error: 'Not Found', path: pathname });
        }
        return;
      }

      const handler = allHandlers[idx++];
      try {
        handler(req, res, next);
      } catch (e) {
        next(e);
      }
    };

    // Döngüyü başlat
    next();
  }
}

/**
 * Enhanced request object wrapping H3Request
 */
class RouterRequest {
  constructor(h3req, opts) {
    this.raw = h3req;
    this.method = opts.method;
    this.path = opts.pathname;
    this.pathname = opts.pathname;
    this.query = parseQuery(opts.queryString);
    this.headers = h3req.headers || {};
    this.params = {};
    this.body = h3req.body || Buffer.alloc(0);
    this.quicConn = opts.quicConn;

    this.authority = h3req.authority || this.headers[':authority'] || '';
    this.scheme = h3req.scheme || 'https';
  }

  json() {
    try {
      return JSON.parse(this.body.toString('utf8'));
    } catch (_) {
      return null;
    }
  }

  text() {
    return this.body.toString('utf8');
  }
}

/**
 * Enhanced response object wrapping H3Request
 */
class RouterResponse {
  constructor(h3req) {
    this._h3req = h3req;
    this._statusCode = 200;
    this._headers = {};
    this._headersSent = false;
  }

  status(code) {
    this._statusCode = code;
    return this;
  }

  set(name, value) {
    this._headers[name.toLowerCase()] = String(value);
    return this;
  }

  header(name, value) {
    return this.set(name, value);
  }

  send(body) {
    if (this._headersSent) return this;

    if (typeof body === 'object' && !Buffer.isBuffer(body)) {
      return this.json(body);
    }

    if (typeof body === 'string') {
      if (!this._headers['content-type']) {
        this._headers['content-type'] = 'text/plain; charset=utf-8';
      }
    }

    const data = typeof body === 'string' ? Buffer.from(body, 'utf8') : body;
    this._headers['content-length'] = String(data.length);
    this._headersSent = true;
    this._h3req.respond(this._statusCode, this._headers).end(data);
    return this;
  }

  json(obj) {
    if (this._headersSent) return this;

    const body = JSON.stringify(obj);
    this._headers['content-type'] = 'application/json; charset=utf-8';
    this._headers['content-length'] = String(Buffer.byteLength(body));
    this._headersSent = true;
    this._h3req.respond(this._statusCode, this._headers).end(body);
    return this;
  }

  html(content) {
    if (this._headersSent) return this;
    this._headers['content-type'] = 'text/html; charset=utf-8';
    return this.send(content);
  }

  redirect(url, permanent = false) {
    if (this._headersSent) return this;
    this._statusCode = permanent ? 301 : 302;
    this._headers['location'] = url;
    this._headers['content-length'] = '0';
    this._headersSent = true;
    this._h3req.respond(this._statusCode, this._headers).end();
    return this;
  }

  end(data) {
    if (this._headersSent && !data) return this;
    if (data) return this.send(data);
    this._headersSent = true;
    this._h3req.respond(this._statusCode, this._headers).end();
    return this;
  }
}

// ----- Helpers -----

function compilePath(path) {
  const paramNames = [];
  const parts = path.split('/');
  const regexParts = parts.map(part => {
    if (part.startsWith(':')) {
      paramNames.push(part.slice(1));
      return '([^/]+)';
    }
    if (part === '*') {
      paramNames.push('wildcard');
      return '(.*)';
    }
    return escapeRegex(part);
  });
  const regex = new RegExp('^' + regexParts.join('/') + '$');
  return { regex, paramNames };
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function parseQuery(qs) {
  if (!qs) return {};
  const params = {};
  const parts = qs.split('&');
  for (const part of parts) {
    const eqIdx = part.indexOf('=');
    if (eqIdx >= 0) {
      const key = decodeURIComponent(part.slice(0, eqIdx));
      const val = decodeURIComponent(part.slice(eqIdx + 1));
      params[key] = val;
    } else {
      params[decodeURIComponent(part)] = '';
    }
  }
  return params;
}

module.exports = { Router, RouterRequest, RouterResponse };