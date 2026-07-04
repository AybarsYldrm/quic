'use strict';

const { createLogger } = require('../utils/logger');
const { composePolicy, ReplayCache } = require('../crypto/early-data-policy'); 

const log = createLogger('Router');

const replayCache = new ReplayCache({ ttlMs: 10000, maxSize: 5000 });
const earlyDataPolicy = composePolicy({
  requireSafe: true,
  replayCache: replayCache
});

class Router {
  constructor(options = {}) {
    this.stack = [];
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
      this.stack.push({ type: 'middleware', path: null, handler: pathOrFn });
    } else {
      this.stack.push({ type: 'middleware', path: pathOrFn, handler: fn });
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
    this.stack.push({ type: 'route', method, path, regex, paramNames, handlers });
    return this;
  }

  handle(h3req, quicConn) {
    const method = (h3req.method || 'GET').toUpperCase();
    const rawPath = h3req.path || '/';
    const qIdx = rawPath.indexOf('?');
    
    const pathname = qIdx >= 0 ? rawPath.slice(0, qIdx) : rawPath;
    const queryString = qIdx >= 0 ? rawPath.slice(qIdx + 1) : '';

    const req = new RouterRequest(h3req, { method, pathname, queryString, quicConn });
    const res = new RouterResponse(h3req);

    if (quicConn && req.raw && req.raw.stream) {
      if (quicConn.is0RTT && quicConn.is0RTT(req.raw.stream.id)) {
        
        const ticketNonce = typeof quicConn.get0RTTNonce === 'function'
          ? quicConn.get0RTTNonce()
          : null;

        const ctx = ticketNonce ? { ticketNonce } : {};
        const policyResult = earlyDataPolicy(req, ctx);

        if (policyResult.accept) {
          res.set('Early-Data', '1');
        } else {
          log.warn(`[SECURITY] 0-RTT denied (reason=${policyResult.reason}, path=${pathname})`);
          res.status(425).json({
            status: 'error',
            message: 'Too Early. Request not allowed in 0-RTT or replay detected.',
            reason: policyResult.reason
          });
          return;
        }
      }
    }

    if (!res._headers['alt-svc']) {
      res.set('alt-svc', `h3=":${this.altSvcPort}"; ma=86400`);
    }
    if (this.cors && !res._headers['access-control-allow-origin']) {
      res.set('access-control-allow-origin', this.cors.origin);
      res.set('vary', 'Origin');
    }

    if (method === 'OPTIONS' && this.cors) {
      let explicit = false;
      for (const layer of this.stack) {
        if (layer.type === 'route' && (layer.method === 'OPTIONS' || layer.method === '*')) {
          if (layer.regex.test(pathname)) { explicit = true; break; }
        }
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

    for (const layer of this.stack) {
      if (layer.type === 'middleware') {
        if (!layer.path || pathname.startsWith(layer.path)) {
          allHandlers.push(layer.handler);
        }
      } else if (layer.type === 'route') {
        if (layer.method !== '*' && layer.method !== method) continue;
        const match = layer.regex.exec(pathname);
        if (match) {
          for (const h of layer.handlers) {
            allHandlers.push((req, res, next) => {
              const params = {};
              for (let i = 0; i < layer.paramNames.length; i++) {
                params[layer.paramNames[i]] = decodeURIComponent(match[i + 1]);
              }
              req.params = Object.assign(req.params || {}, params);
              h(req, res, next);
            });
          }
        }
      }
    }

    let idx = 0;
    const next = (err) => {
      if (err) {
        log.error('Route handler error:', err.message || err);
        if (!res._headersSent) {
          res.status(500).json({ error: 'Internal Server Error' });
        }
        return;
      }

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
    this.url = h3req.path || h3req.url || '/';
    this.originalUrl = this.url;
    this.query = parseQuery(opts.queryString);
    this.params = {};
    this.quicConn = opts.quicConn;

    // KRİTİK FİX BURADA:
    // Sizin gateway.js veya test.js dosyanızdaki bir kod satırı `req.headers` objesini 
    // sadece pseudo-header kalacak şekilde yanlışlıkla eziyor/silerek üstüne yazıyor! 
    // Bunun önüne geçmek için http3.js içinde biriktirdiğimiz ezilemez (Shadow) `_realHeaders` kopyasını çekiyoruz.
    const safeHeaders = h3req._realHeaders || h3req.headers || {};
    this.headers = Object.assign({}, safeHeaders);
    
    // Uygulamanızın konsol (console.log) çıktılarını ve parserlarını rahatlatmak için 
    // tam ve eksiksiz rawHeaders dizisini yeniden oluşturuyoruz.
    this.rawHeaders = h3req.rawHeaders || Object.entries(this.headers).flat();
    
    if (this.raw) {
      // Sizin projenizdeki .headers referanslarını da (Eğer okumaya çalışıyorsa)
      // eksiksiz tam liste ile güncelliyoruz, böylece boş veya 4 elemanlı gelmez.
      this.raw.headers = this.headers;
    }

    const rawCookie = this.headers.cookie || this.headers.Cookie || '';
    this.cookies = this._parseCookies(rawCookie);
    
    this.authority = h3req.authority || this.headers[':authority'] || '';
    this.scheme = h3req.scheme || 'https';
  }

  // Güvenli Cookie Ayrıştırıcı
  _parseCookies(cookieStr) {
    const parsed = {};
    if (!cookieStr) return parsed;
    cookieStr.split(';').forEach(cookie => {
      const parts = cookie.split('=');
      if (parts.length >= 2) {
        parsed[parts[0].trim()] = parts.slice(1).join('=').trim();
      }
    });
    return parsed;
  }

  get body() {
    return this.raw.body || Buffer.alloc(0);
  }

  json() {
    try {
      if (this.body.length === 0) return null;
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

  get statusCode() { return this._statusCode; }
  set statusCode(code) { this._statusCode = code; }

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