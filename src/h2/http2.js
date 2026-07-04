'use strict';

const { EventEmitter } = require('events');
const { createLogger } = require('../utils/logger');
const { HpackEncoder, HpackDecoder } = require('./hpack');

const log = createLogger('HTTP2');

const H2_FRAME = {
  DATA:          0x00, HEADERS:       0x01, PRIORITY:      0x02, RST_STREAM:    0x03,
  SETTINGS:      0x04, PUSH_PROMISE:  0x05, PING:          0x06, GOAWAY:        0x07,
  WINDOW_UPDATE: 0x08, CONTINUATION:  0x09,
};

const H2_SETTINGS = {
  HEADER_TABLE_SIZE: 1, ENABLE_PUSH: 2, MAX_CONCURRENT_STREAMS: 3,
  INITIAL_WINDOW_SIZE: 4, MAX_FRAME_SIZE: 5, MAX_HEADER_LIST_SIZE: 6,
};

const H2_ERROR = {
  NO_ERROR: 0x00, PROTOCOL_ERROR: 0x01, INTERNAL_ERROR: 0x02, FLOW_CONTROL_ERROR: 0x03,
  SETTINGS_TIMEOUT: 0x04, STREAM_CLOSED: 0x05, FRAME_SIZE_ERROR: 0x06, REFUSED_STREAM: 0x07,
  CANCEL: 0x08, COMPRESSION_ERROR: 0x09, CONNECT_ERROR: 0x0a, ENHANCE_YOUR_CALM: 0x0b,
  INADEQUATE_SECURITY: 0x0c, HTTP_1_1_REQUIRED: 0x0d,
};

function encodeSettings(settings) {
  const parts = [];
  for (const [id, value] of Object.entries(settings)) {
    const buf = Buffer.alloc(6);
    buf.writeUInt16BE(Number(id), 0);
    buf.writeUInt32BE(Number(value), 2);
    parts.push(buf);
  }
  return Buffer.concat(parts);
}

function decodeSettings(payload) {
  const settings = {};
  let offset = 0;
  while (offset + 6 <= payload.length) {
    const id  = payload.readUInt16BE(offset);
    const val = payload.readUInt32BE(offset + 2);
    settings[String(id)] = val;
    offset += 6;
  }
  return settings;
}

function buildH2Settings(cfg = {}) {
  const s = {
    [H2_SETTINGS.HEADER_TABLE_SIZE]:      cfg.headerTableSize      ?? 4096,
    [H2_SETTINGS.ENABLE_PUSH]:            cfg.enablePush           ?? 0,
    [H2_SETTINGS.MAX_CONCURRENT_STREAMS]: cfg.maxConcurrentStreams ?? 100,
    [H2_SETTINGS.INITIAL_WINDOW_SIZE]:    cfg.initialWindowSize    ?? 65535,
    [H2_SETTINGS.MAX_FRAME_SIZE]:         cfg.maxFrameSize         ?? 16384,
    [H2_SETTINGS.MAX_HEADER_LIST_SIZE]:   cfg.maxHeaderListSize    ?? 65536,
  };
  return Object.freeze(s);
}

class H2Connection extends EventEmitter {
  constructor(tcpEdgeConnection, options = {}) {
    super();
    this.tcp      = tcpEdgeConnection;
    this.isServer = options.isServer || false;

    this.localSettings = options.settings ? options.settings : buildH2Settings();
    this.peerSettings  = {};

    const tableSize = this.localSettings[H2_SETTINGS.HEADER_TABLE_SIZE] ?? 4096;
    this._hpackEncoder = new HpackEncoder(tableSize);
    this._hpackDecoder = new HpackDecoder(tableSize);

    this.activeRequests = new Map();
    this.ready          = false;
    this.goawayId       = null;

    this._init();
  }

  _encodeHeaders(headersArray) {
    return this._hpackEncoder.encode(headersArray);
  }

  _decodeHeaders(buf) {
    try {
      return this._hpackDecoder.decode(buf);
    } catch (err) {
      log.error('HPACK Decode Error: ' + err.message);
      this.emit('error', Object.assign(err, { code: H2_ERROR.COMPRESSION_ERROR }));
      return [];
    }
  }

  _applyPeerSettings(settings) {
    this.peerSettings = { ...this.peerSettings, ...settings };
    const peerTableSize = settings[H2_SETTINGS.HEADER_TABLE_SIZE];
    if (peerTableSize !== undefined) {
      this._hpackEncoder.setMaxTableSize(peerTableSize);
    }
  }

  _applyLocalSettings(settings) {
    this.localSettings = { ...this.localSettings, ...settings };
    const localTableSize = settings[H2_SETTINGS.HEADER_TABLE_SIZE];
    if (localTableSize !== undefined) {
      this._hpackDecoder.setMaxTableSize(localTableSize);
    }
  }

  _init() {
    this.tcp.on('stream', (stream, rawHeaders) => {
      const initialHeaders = rawHeaders
        ? (Buffer.isBuffer(rawHeaders) ? this._decodeHeaders(rawHeaders) : rawHeaders)
        : null;
      this._handleStream(stream, initialHeaders);
    });

    this.tcp.on('remoteSettings', (rawSettings) => {
      this._applyPeerSettings(rawSettings);
    });

    this.tcp.on('goaway', (info) => {
      const errorCode = info ? info.errorCode : H2_ERROR.NO_ERROR;
      this._handleGoaway(this.goawayId || 0, errorCode);
    });

    if (!this.ready) {
      this.ready = true;
      queueMicrotask(() => this.emit('ready'));
    }
  }

  _handleGoaway(lastStreamId, errorCode) {
    this.goawayId = lastStreamId;
    for (const [streamId, req] of this.activeRequests) {
      if (streamId > this.goawayId) {
        req.emit('error', new Error(`Stream ${streamId} rejected by GOAWAY (Code: ${errorCode})`));
        this.activeRequests.delete(streamId);
      }
    }
    this.emit('goaway', this.goawayId);
  }

  _handleStream(stream, initialHeaders) {
    const request = new H2Request(stream, this, this.isServer);
    const sid = stream.id || stream.streamId;
    this.activeRequests.set(sid, request);

    let requestEmitted = false;

    const tryEmitRequest = () => {
      if (this.isServer && !requestEmitted && request._headersReceived) {
        requestEmitted = true;
        this.emit('request', request);
      }
    };

    if (initialHeaders) {
      request._handleHeaders(initialHeaders);
      tryEmitRequest();
    }

    stream.on('headers', (rawOrDecoded, endStream) => {
      const headers = Buffer.isBuffer(rawOrDecoded)
        ? this._decodeHeaders(rawOrDecoded)
        : rawOrDecoded;
      request._handleHeaders(headers);
      tryEmitRequest();
      if (endStream) request._handleEnd();
    });

    stream.on('end', () => {
      if (this.isServer && !requestEmitted) {
        if (!request.method) request.method = 'GET';
        if (!request.path)   request.path   = '/';
        requestEmitted = true;
        this.emit('request', request);
      }
      request._handleEnd();
      this.activeRequests.delete(sid);
    });

    stream.on('error', (err) => {
      request.emit('error', err);
      this.activeRequests.delete(sid);
    });
  }

  request(method, path, headers = {}, options = {}) {
    if (this.goawayId !== null) {
      const dummy = new H2Request(null, this, false);
      queueMicrotask(() => dummy.emit('error', new Error('Connection is going away')));
      return dummy;
    }

    const stream = this.tcp.createStream(true);
    const req    = new H2Request(stream, this, false);
    const sid    = stream.id || stream.streamId;
    this.activeRequests.set(sid, req);

    const allHeaders = [
      [':method',    method],
      [':path',      path],
      [':scheme',    options.scheme    || 'https'],
      [':authority', options.authority || this.tcp?.tls?.serverName || 'localhost'],
    ];
    for (const [k, v] of Object.entries(headers)) allHeaders.push([k.toLowerCase(), String(v)]);

    const encodedHeaders = this._encodeHeaders(allHeaders);
    if (typeof this.tcp.sendHeaders === 'function') {
      this.tcp.sendHeaders(sid, encodedHeaders, options.endStream || false);
    }

    stream.on('headers', (rawOrDecoded, endStream) => {
      const decoded = Buffer.isBuffer(rawOrDecoded) ? this._decodeHeaders(rawOrDecoded) : rawOrDecoded;
      req._handleHeaders(decoded);
      if (endStream) req._handleEnd();
    });

    stream.on('end', () => {
      req._handleEnd();
      this.activeRequests.delete(sid);
    });

    stream.on('error', (err) => this.activeRequests.delete(sid));

    req._headersSent = true;
    return req;
  }

  close(errorCode = H2_ERROR.NO_ERROR) {
    if (typeof this.tcp.close === 'function') this.tcp.close(errorCode);
  }
}

class H2Request extends EventEmitter {
  constructor(stream, h2conn, isServer) {
    super();
    this.stream   = stream;
    this.h2       = h2conn;
    this.isServer = isServer;

    this.headers  = null;
    this._realHeaders = null;
    this.rawHeaders = null; // HTTP/3 ile simetrik yapıldı
    
    this.trailers = null;
    this.body     = Buffer.alloc(0);

    this._headersSent     = false;
    this._headersReceived = false;
    this._complete        = false;
    this._responseHeaders = {};

    this.method    = null;
    this.path      = null;
    this.scheme    = null;
    this.authority = null;
    this.status    = null;

    if (this.stream) {
      this.stream.on('data', (chunk) => {
        this.body = Buffer.concat([this.body, chunk]);
        this.emit('data', chunk);
      });
    }
  }

  get url() { return this.path || '/'; }
  get originalUrl() { return this.path || '/'; }
  
  get socket() { return this.h2.tcp.socket || {}; }

  // YENİDEN YAZILAN KISIM: HTTP/3 dosyası ile BİREBİR simetrik hale getirildi.
  // Eskiden pseudo-headerlar yutuluyordu, artık hepsi headers objesine eksiksiz giriyor.
  _handleHeaders(decodedHeaders) {
    if (!this._headersReceived) {
      this._headersReceived = true;
      this.headers = {};
      this._realHeaders = {};

      for (const [name, value] of decodedHeaders) {
        const lowerName = String(name || '').toLowerCase();
        const strValue  = String(value ?? '');
        
        if (!lowerName) continue;

        const existing = this.headers[lowerName];
        let finalVal = strValue;

        if (existing === undefined) {
          finalVal = strValue;
        } else if (lowerName === 'cookie') {
          finalVal = `${existing}; ${strValue}`;
        } else if (lowerName === 'set-cookie') {
          finalVal = Array.isArray(existing) ? [...existing, strValue] : [existing, strValue];
        } else {
          finalVal = `${existing}, ${strValue}`;
        }

        // Tüm headerları (pseudo dahil) asıl objeye kaydet (Eski H2 uygulamasında yutuluyordu)
        this.headers[lowerName] = finalVal;
        this._realHeaders[lowerName] = finalVal;

        if (lowerName === ':method') this.method = strValue;
        if (lowerName === ':path') { this.path = strValue; }
        if (lowerName === ':scheme') this.scheme = strValue;
        if (lowerName === ':authority') { 
          this.authority = strValue;
          // Standart router uyumluluğu için "host" headerı da doldurulur
          if (!this.headers['host']) this.headers['host'] = strValue;
        }
        if (lowerName === ':status') this.status = parseInt(strValue, 10);
      }
      
      // H3 yapısı ile simetri sağlaması için rawHeaders parametresini de bağladık
      this.rawHeaders = Object.entries(this.headers).flat();

      this.emit('headers', this.headers);
    } else {
      this.trailers = this.trailers || {};
      for (const [name, value] of decodedHeaders) {
        if (name) this.trailers[String(name).toLowerCase()] = String(value ?? '');
      }
      this.emit('trailers', this.trailers);
    }
  }

  _handleEnd() {
    if (!this._complete) {
      this._complete = true;
      this.emit('end');
    }
  }

  set(key, val) {
    this._responseHeaders[key.toLowerCase()] = String(val);
    return this;
  }

  respond(statusCode, headers = {}, endStream = false) {
    if (this._headersSent) return this;

    const allHeaders    = [[':status', String(statusCode)]];
    const mergedHeaders = { ...this._responseHeaders, ...headers };
    for (const [k, v] of Object.entries(mergedHeaders)) allHeaders.push([k.toLowerCase(), String(v)]);

    this._headersSent = true;
    this._safeWriteHeaders(allHeaders, endStream);
    return this;
  }

  sendData(data, endStream = false) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data || ''));
    if (buf.length === 0 && !endStream) return this;
    
    this._safeWrite(buf, endStream);
    return this;
  }

  end(data) {
    const hasData = data !== undefined && data !== null && String(data).length > 0;
    
    if (!this._headersSent) {
      this.respond(this.status || 200, {}, !hasData);
    }
    
    if (hasData) {
      this.sendData(data, true);
    } else if (this._headersSent) {
      this.sendData(Buffer.alloc(0), true);
    }
    
    this._handleEnd();
    return this;
  }

  _safeWriteHeaders(headersArray, endStream = false) {
    try {
      const encoded = this.h2._encodeHeaders(headersArray);
      const sid = this.stream.id || this.stream.streamId;
      
      if (this.h2.tcp && typeof this.h2.tcp.sendHeaders === 'function') {
        this.h2.tcp.sendHeaders(sid, encoded, endStream);
      } else if (typeof this.stream.sendHeaders === 'function') {
        this.stream.sendHeaders(encoded, { endStream });
      }
    } catch (e) {
      log.warn('H2 stream write headers failed:', e.message);
    }
  }

  _safeWrite(buf, endStream = false) {
    try { 
      const sid = this.stream.id || this.stream.streamId;
      if (this.h2.tcp && typeof this.h2.tcp.sendData === 'function') {
        this.h2.tcp.sendData(sid, buf, endStream);
      } else if (this.h2.tcp && typeof this.h2.tcp._sendData === 'function') {
        this.h2.tcp._sendData(sid, buf, endStream);
      } else {
        if (typeof this.stream.write === 'function') this.stream.write(buf);
        if (endStream && typeof this.stream.end === 'function') this.stream.end();
      }
    }
    catch (e) { log.warn('H2 stream write failed:', e.message); }
  }

  write(data) {
    if (!this._headersSent) this.respond(200);
    this.sendData(data);
    return this;
  }

  endRequest(data) {
    return this.end(data);
  }

  json(data) {
    if (!this._headersSent) {
      this.set('content-type', 'application/json; charset=utf-8');
      this.respond(this.status || 200);
    }
    this.end(Buffer.from(JSON.stringify(data)));
    return this;
  }
}

module.exports = {
  H2Connection, H2Request, H2_FRAME, H2_SETTINGS, H2_ERROR,
  encodeSettings, decodeSettings, buildH2Settings,
};