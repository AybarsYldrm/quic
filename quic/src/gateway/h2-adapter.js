'use strict';

const { EventEmitter } = require('events');

class H2StreamAdapter extends EventEmitter {
  constructor(stream, headers, options = {}) {
    super();
    this.stream = stream;
    this.headers = headers;
    this.method = (headers[':method'] || 'GET').toUpperCase();
    this.path = headers[':path'] || '/';
    this.transport = 'h2';
    this.body = Buffer.alloc(0);
    this.altSvc = options.altSvc || null;
    this._responseHeaders = {};
    
    // KRİTİK: Eğer stream biz adaptörü kurana kadar çoktan bittiyse bunu yakala
    this._complete = stream.readableEnded || false;

    const chunks = [];
    stream.on('data', (c) => chunks.push(c));
    
    stream.on('end', () => {
      this.body = Buffer.concat(chunks);
      this._complete = true;
      this.emit('end');
    });

    // Eğer çoktan bittiyse, 'end' eventini zorla tetikle ki Router askıda kalmasın
    if (this._complete) {
      process.nextTick(() => this.emit('end'));
    }
  }

  set(key, val) {
    this._responseHeaders[key.toLowerCase()] = val;
  }

  respond(status, headers = {}) {
    const finalHeaders = {
      ':status': status,
      ...this._responseHeaders,
      ...headers
    };

    if (this.altSvc && !finalHeaders['alt-svc']) {
      finalHeaders['alt-svc'] = this.altSvc;
    }

    try {
      // Eğer stream client tarafından koparıldıysa yazmaya çalışma, çökmeyi engeller
      if (!this.stream.headersSent && !this.stream.destroyed && !this.stream.closed) {
        this.stream.respond(finalHeaders);
      }
    } catch (e) {
      console.error(`[H2] Headers error: ${e.message}`);
    }

    const stream = this.stream;
    return {
      write: (chunk) => {
        if (chunk && !stream.destroyed) stream.write(chunk);
        return this;
      },
      end: (chunk) => {
        if (!stream.destroyed) {
          if (chunk) stream.end(chunk);
          else stream.end();
        }
      },
      json: (data) => {
        const buf = Buffer.from(JSON.stringify(data));
        try {
          if (!stream.headersSent && !stream.destroyed) {
            finalHeaders['content-type'] = 'application/json';
            stream.respond(finalHeaders);
          }
          if (!stream.destroyed) stream.end(buf);
        } catch (e) {
           // Client bağlantıyı kapattıysa görmezden gel
        }
      }
    };
  }
}

class Http1RequestAdapter extends EventEmitter {
  constructor(req, res, options = {}) {
    super();
    this._req = req;
    this._res = res;
    this.headers = req.headers;
    this.method = (req.method || 'GET').toUpperCase();
    this.path = req.url || '/';
    this.transport = 'h1';
    this.body = Buffer.alloc(0);
    this.altSvc = options.altSvc || null;
    
    // HTTP/1.1 için state kontrolü
    this._complete = req.readableEnded || req.complete || false;

    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    
    req.on('end', () => {
      this.body = Buffer.concat(chunks);
      this._complete = true;
      this.emit('end');
    });

    if (this._complete) {
      process.nextTick(() => this.emit('end'));
    }
  }

  set(key, val) {
    if (!this._res.headersSent) this._res.setHeader(key, val);
  }

  respond(status, headers = {}) {
    if (this.altSvc && !this._res.headersSent) this._res.setHeader('alt-svc', this.altSvc);
    
    if (!this._res.headersSent) {
      for (const [k, v] of Object.entries(headers)) {
        this._res.setHeader(k, v);
      }
      this._res.statusCode = status;
    }
    
    const res = this._res;

    return {
      write: (chunk) => {
        if (!res.destroyed) res.write(chunk);
        return this;
      },
      end: (chunk) => {
        if (!res.destroyed) res.end(chunk);
      },
      json: (data) => {
        if (!res.headersSent && !res.destroyed) {
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify(data));
        }
      }
    };
  }
}

module.exports = { H2StreamAdapter, Http1RequestAdapter };