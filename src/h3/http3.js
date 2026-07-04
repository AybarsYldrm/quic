'use strict';

const { EventEmitter } = require('events');
const { QpackEncoder, QpackDecoder, decodePrefixInt: qpackDecodePrefixInt } = require('./qpack');
const { decodeVarInt, encodeVarInt } = require('../transport/varint');
const { createLogger } = require('../utils/logger');

const log = createLogger('HTTP3');

const H3_FRAME = { DATA: 0x00, HEADERS: 0x01, CANCEL_PUSH: 0x03, SETTINGS: 0x04, PUSH_PROMISE: 0x05, GOAWAY: 0x07, MAX_PUSH_ID: 0x0d };
const H3_SETTINGS = { QPACK_MAX_TABLE_CAPACITY: 0x01, MAX_FIELD_SECTION_SIZE: 0x06, QPACK_BLOCKED_STREAMS: 0x07, ENABLE_CONNECT_PROTOCOL: 0x08, H3_DATAGRAM: 0x33, ENABLE_WEBTRANSPORT: 0x2b603742 };
const H3_ERROR = { NO_ERROR: 0x0100, GENERAL_PROTOCOL_ERROR: 0x0101, INTERNAL_ERROR: 0x0102, STREAM_CREATION_ERROR: 0x0103, CLOSED_CRITICAL_STREAM: 0x0104, FRAME_UNEXPECTED: 0x0105, FRAME_ERROR: 0x0106 };
const UNI_STREAM_TYPE = { CONTROL: 0x00, PUSH: 0x01, QPACK_ENCODER: 0x02, QPACK_DECODER: 0x03, WEBTRANSPORT: 0x54 };
const WT_BIDI_STREAM_PREFIX = 0x41;

function encodeH3Frame(type, payload) {
  return Buffer.concat([encodeVarInt(type), encodeVarInt(payload.length), payload]);
}

function decodeH3Frame(buf, offset = 0) {
  if (offset >= buf.length) return null;
  try {
    const { value: type, length: tLen } = decodeVarInt(buf, offset);
    offset += tLen;
    if (offset >= buf.length) return null;
    const { value: payloadLen, length: pLen } = decodeVarInt(buf, offset);
    offset += pLen;
    if (offset + payloadLen > buf.length) return null;
    const payload = buf.subarray(offset, offset + Number(payloadLen));
    return { type: Number(type), payload, totalLength: tLen + pLen + Number(payloadLen) };
  } catch (_) {
    return null;
  }
}

function encodeSettings(settings) {
  const parts = [];
  for (const [id, value] of Object.entries(settings)) {
    parts.push(encodeVarInt(Number(id)));
    parts.push(encodeVarInt(Number(value)));
  }
  return encodeH3Frame(H3_FRAME.SETTINGS, Buffer.concat(parts));
}

function decodeSettings(payload) {
  const settings = {};
  let offset = 0;
  while (offset < payload.length) {
    try {
      const { value: id,  length: idLen  } = decodeVarInt(payload, offset);
      offset += idLen;
      const { value: val, length: valLen } = decodeVarInt(payload, offset);
      offset += valLen;
      settings[String(id)] = Number(val);
    } catch (_) { break; }
  }
  return settings;
}

function buildH3Settings(cfg = {}) {
  const s = {
    [H3_SETTINGS.QPACK_MAX_TABLE_CAPACITY]: 4096,
    [H3_SETTINGS.MAX_FIELD_SECTION_SIZE]:   cfg.maxFieldSectionSize ?? 65536,
    [H3_SETTINGS.QPACK_BLOCKED_STREAMS]:    100,
  };
  if (cfg.enableWebTransport) {
    s[H3_SETTINGS.ENABLE_CONNECT_PROTOCOL]   = 1;
    s[H3_SETTINGS.H3_DATAGRAM]               = 1;
    s[H3_SETTINGS.ENABLE_WEBTRANSPORT]       = 1;
  }
  return Object.freeze(s);
}

class H3Connection extends EventEmitter {
  constructor(quicConnection, options = {}) {
    super();
    this.quic     = quicConnection;
    this.isServer = options.isServer || false;
    
    this.encoder  = new QpackEncoder({ maxTableCapacity: 4096 });
    this.decoder  = new QpackDecoder({ maxTableCapacity: 4096 });
    this.enableWebTransport = options.enableWebTransport || false;

    const rawSettings = options.settings
      ? options.settings
      : buildH3Settings({ enableWebTransport: this.enableWebTransport });

    const base = { ...rawSettings };
    base[H3_SETTINGS.QPACK_MAX_TABLE_CAPACITY] = 4096;
    base[H3_SETTINGS.QPACK_BLOCKED_STREAMS]    = 100;
    this.localSettings = Object.freeze(base);

    this.peerSettings             = {};
    this.peerSupportsWebTransport = false;

    this.localControlStream  = null;
    this.peerControlStream   = null;
    this.qpackEncoderStream  = null;
    this.qpackDecoderStream  = null;

    this.activeRequests  = new Map();
    this._blockedStreams = new Map();
    this.ready     = false;
    this.goawayId  = null;

    this._init();
  }

  _init() {
    if (this.isServer) {
      const impl = this.quic._impl || this.quic;
      if (impl) impl.nextUniStreamId = 3;
    }

    this.localControlStream = this.quic.createStream(false);
    const settingsFrame = encodeSettings(this.localSettings);
    this.localControlStream.write(Buffer.concat([Buffer.from([0x00]), settingsFrame]));

    this.qpackEncoderStream = this.quic.createStream(false);
    this.qpackEncoderStream.write(Buffer.from([0x02]));

    this.qpackDecoderStream = this.quic.createStream(false);
    this.qpackDecoderStream.write(Buffer.from([0x03]));

    this.ready = true;

    const conn = this.quic._impl || this.quic;
    if (conn && typeof conn._flushAll === 'function') {
      setImmediate(() => { try { conn._flushAll(); } catch {} });
    }

    queueMicrotask(() => this.emit('ready'));
    this.quic.on('stream', (stream) => this._handleStream(stream));

    if (conn && conn.streams) {
      for (const stream of conn.streams.values()) {
        this._handleStream(stream);
      }
    }

    this.quic.on('datagram', (raw) => {
      try {
        const { value: quarter, length: qLen } = decodeVarInt(raw, 0);
        const sessionId = Number(quarter) * 4;
        const payload = raw.subarray(qLen);
        this.emit('h3datagram', sessionId, payload);
      } catch (_) {}
    });
  }

  sendH3Datagram(sessionStreamId, data) {
    if (typeof data === 'string') data = Buffer.from(data, 'utf8');
    if ((sessionStreamId & 0x03) !== 0) throw new Error('H3 datagram session id must be a client-initiated bidi stream');
    const quarter = Math.floor(sessionStreamId / 4);
    const framed = Buffer.concat([encodeVarInt(quarter), data]);
    return this.quic.sendDatagram(framed);
  }

  _handleStream(stream) {
    if (stream._h3Handled) return;
    stream._h3Handled = true;

    const id = stream.id;
    const isBidi = (id & 0x02) === 0;
    if (isBidi) this._peekBidiStreamType(stream);
    else this._readUniStreamType(stream);
  }

  _readUniStreamType(stream) {
    let typeBuf = Buffer.alloc(0);
    const onData = (chunk) => {
      typeBuf = Buffer.concat([typeBuf, chunk]);
      if (typeBuf.length === 0) return;
      try {
        const { value: streamType, length: tLen } = decodeVarInt(typeBuf, 0);
        stream.removeListener('data', onData);
        const rest = typeBuf.subarray(tLen);
        this._handleUniStream(stream, Number(streamType), rest);
      } catch (e) { }
    };
    stream.on('data', onData);
  }

  _handleUniStream(stream, streamType, initialData) {
    switch (streamType) {
      case UNI_STREAM_TYPE.CONTROL:
        this.peerControlStream = stream;
        this._processControlStream(stream, initialData);
        break;
      case UNI_STREAM_TYPE.QPACK_ENCODER:
        this._processQpackEncoderStream(stream, initialData);
        break;
      case UNI_STREAM_TYPE.QPACK_DECODER:
        this._processQpackDecoderStream(stream, initialData);
        break;
      case UNI_STREAM_TYPE.WEBTRANSPORT:
        this._processWebTransportUniStream(stream, initialData);
        break;
    }
  }

  _processQpackDecoderStream(stream, initialData) {
    stream.on('data', () => {});
  }

  _processWebTransportUniStream(stream, initialData) {
    let buf = initialData || Buffer.alloc(0);
    const tryDispatch = () => {
      if (buf.length === 0) return false;
      try {
        const { value: sid, length: sLen } = decodeVarInt(buf, 0);
        const rest = buf.subarray(sLen);
        buf = Buffer.alloc(0);
        stream.removeListener('data', onData);
        this.emit('wtUniStream', Number(sid), stream, rest);
        return true;
      } catch (_) { return false; }
    };
    const onData = (chunk) => { buf = Buffer.concat([buf, chunk]); tryDispatch(); };
    if (!tryDispatch()) stream.on('data', onData);
  }

  _processControlStream(stream, initialData) {
    let buf = initialData || Buffer.alloc(0);
    const processBuffer = () => {
      while (buf.length > 0) {
        const frame = decodeH3Frame(buf, 0);
        if (!frame) break;
        buf = buf.subarray(frame.totalLength);
        this._handleControlFrame(frame);
      }
    };
    processBuffer();
    stream.on('data', (chunk) => { buf = Buffer.concat([buf, chunk]); processBuffer(); });
  }

  _handleControlFrame(frame) {
    switch (frame.type) {
      case H3_FRAME.SETTINGS:
        this.peerSettings = decodeSettings(frame.payload);
        break;
      case H3_FRAME.GOAWAY:
        if (frame.payload.length >= 1) {
          try {
            const { value: id } = decodeVarInt(frame.payload, 0);
            this.goawayId = Number(id);
            for (const [streamId, req] of this.activeRequests) {
              if (streamId >= this.goawayId) {
                // See http2.js _handleGoaway: don't crash callers that never
                // attached an 'error' listener (Node throws on unhandled
                // 'error' emissions with none registered).
                if (req.listenerCount('error') > 0) {
                  req.emit('error', new Error(`Stream ${streamId} rejected by GOAWAY`));
                }
                this.activeRequests.delete(streamId);
              }
            }
            this.emit('goaway', this.goawayId);
          } catch (_) {}
        }
        break;
    }
  }

  _processQpackEncoderStream(stream, initialData) {
    const processChunk = (chunk) => {
      try {
        this.decoder.processEncoderInstruction(chunk);
        this._unblockStreams();
      } catch(e) {
        log.error('[H3] QPACK Encoder Parse Hatasi:', e.message);
      }
    };
    if (initialData && initialData.length > 0) processChunk(initialData);
    stream.on('data', processChunk);
  }

  _unblockStreams() {
    if (!this._blockedStreams) return;
    for (const [sid, entry] of this._blockedStreams.entries()) {
      if (this.decoder.dynamicTable.insertCount >= entry.requiredInserts) {
        clearTimeout(entry.timeout);
        this._blockedStreams.delete(sid);
        
        try { entry.request._handleFrame(entry.pendingFrame); } catch (e) {}

        if (typeof entry.request._tryEmitRequest === 'function') {
          entry.request._tryEmitRequest();
        }
        if (typeof entry.request._resumeProcessing === 'function') {
          entry.request._resumeProcessing(entry.remainingBuf);
        }
      }
    }
  }

  // Claude'un önerdiği Race-Condition engelleyici Stream Pause/Resume mekanizması
  _peekBidiStreamType(stream) {
    if (typeof stream.pause === 'function') stream.pause();

    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length === 0) return;
      try {
        const { value: firstVarint } = decodeVarInt(buf, 0);
        if (Number(firstVarint) === WT_BIDI_STREAM_PREFIX) {
           // WT Handling
        }
        stream.removeListener('data', onData);
        this._handleRequestStream(stream, buf);

        if (typeof stream.resume === 'function') stream.resume();
      } catch (e) {
        log.error(`[H3] bidiStream dispatch failed:`, e.message);
      }
    };
    stream.on('data', onData);
  }

  _handleRequestStream(stream, seed) {
    const request = new H3Request(stream, this, this.isServer);
    this.activeRequests.set(stream.id, request);

    let buf = seed && seed.length > 0 ? Buffer.from(seed) : Buffer.alloc(0);
    let requestEmitted = false;
    let isBlocked = false;
    let isStreamEnded = false;

    const tryEmitRequest = () => {
      if (this.isServer && !requestEmitted && request._headersReceived) {
        requestEmitted = true;
        try { 
          request.rawHeaders = Object.entries(request.headers || {}).flat();
          this.emit('request', request); 
        }
        catch (err) { log.error(`[H3] 'request' handler threw:`, err.message); }
      }
    };
    request._tryEmitRequest = tryEmitRequest;

    const processBuffer = () => {
      if (isBlocked) return;
      while (buf.length > 0) {
        const frame = decodeH3Frame(buf, 0);
        if (!frame) break;

        if (frame.type === H3_FRAME.HEADERS) {
          try {
            const { value: rawRic } = qpackDecodePrefixInt(frame.payload, 0, 8);
            const ric = rawRic === 0 ? 0 : rawRic - 1;

            if (ric > this.decoder.dynamicTable.insertCount) {
              isBlocked = true;
              const remainingBuf = buf.subarray(frame.totalLength);
              this._blockStream(stream.id, ric, frame, request, remainingBuf);
              buf = Buffer.alloc(0);
              return;
            }
          } catch(e) {
             log.warn('[H3] Header frame RIC decode failed:', e.message);
          }
        }

        buf = buf.subarray(frame.totalLength);
        try { request._handleFrame(frame); } catch (err) {}
        tryEmitRequest();
      }
      
      if (isStreamEnded && buf.length === 0) finalizeRequest();
    };

    const finalizeRequest = () => {
      if (request._isFinalized) return;
      request._isFinalized = true;
      if (this.isServer && !requestEmitted) {
        if (!request.method) request.method = 'GET';
        if (!request.path)   request.path   = '/';
        requestEmitted = true;
        try { this.emit('request', request); } catch (e) {}
      }
      request._handleEnd();
      this.activeRequests.delete(stream.id);
    };

    request._resumeProcessing = (remainingBuf) => {
      isBlocked = false;
      buf = Buffer.concat([remainingBuf, buf]);
      processBuffer();
    };

    // 1. Önce Seed verisini işliyoruz
    if (buf.length > 0) processBuffer();
    
    // 2. İşlendikten sonra yeni veriler için dinleyiciyi kuruyoruz (Duplicate engellendi)
    stream.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (!isBlocked) processBuffer();
    });

    stream.on('end', () => {
      isStreamEnded = true;
      if (!isBlocked) {
        processBuffer();
        if (buf.length === 0) finalizeRequest();
      }
    });

    stream.on('error', () => this.activeRequests.delete(stream.id));
  }

  _blockStream(streamId, requiredInserts, pendingFrame, request, remainingBuf) {
    if (!this._blockedStreams) this._blockedStreams = new Map();
    const entry = { requiredInserts, pendingFrame, request, remainingBuf };
    
    entry.timeout = setTimeout(() => {
      if (this._blockedStreams && this._blockedStreams.has(streamId)) {
        this._blockedStreams.delete(streamId);
        log.warn(`[H3] Stream ${streamId} QPACK Tablo blokaji aciliyor (Fallback)`);
        try { request._handleFrame(pendingFrame); } catch (e) {}
        if (typeof request._tryEmitRequest === 'function') request._tryEmitRequest();
        if (typeof request._resumeProcessing === 'function') request._resumeProcessing(remainingBuf);
      }
    }, 1500);

    this._blockedStreams.set(streamId, entry);
  }

  request(method, path, headers = {}, options = {}) {
    if (this.goawayId !== null) {
      const err = new Error('Connection is going away');
      const dummy = new H3Request(null, this, false);
      queueMicrotask(() => dummy.emit('error', err));
      return dummy;
    }
    const stream = this.quic.createStream(true);
    const req = new H3Request(stream, this, false);
    this.activeRequests.set(stream.id, req);

    const allHeaders = [
      [':method',    method],
      [':path',      path],
      [':scheme',    options.scheme    || 'https'],
      [':authority', options.authority || this.quic?.tls?.serverName || 'localhost'],
    ];
    for (const [k, v] of Object.entries(headers)) allHeaders.push([k.toLowerCase(), String(v)]);

    const { data: encoded } = this.encoder.encode(allHeaders);
    stream.write(encodeH3Frame(H3_FRAME.HEADERS, encoded));
    
    if (options.endStream) {
      try { stream.end(); } catch (e) { log.warn('H3 client stream end failed:', e.message); }
    }

    const t0 = process.hrtime.bigint();
    let bytesIn = 0;
    let responseBuf = Buffer.alloc(0);
    stream.on('data', (chunk) => {
      bytesIn += chunk.length;
      responseBuf = Buffer.concat([responseBuf, chunk]);
      while (responseBuf.length > 0) {
        const frame = decodeH3Frame(responseBuf, 0);
        if (!frame) break;
        responseBuf = responseBuf.subarray(frame.totalLength);
        req._handleFrame(frame);
      }
    });
    stream.on('end', () => {
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      log.info(`H3 ${method} ${path} -> ${req.status || '-'} ${bytesIn}B ${ms.toFixed(1)}ms`);
      req._handleEnd();
    });
    stream.on('error', (err) => {
      log.warn(`H3 ${method} ${path} -> error ${err.message}`);
    });
    req._headersSent = true;
    return req;
  }

  close(errorCode = H3_ERROR.NO_ERROR) {
    this.quic.close(errorCode);
  }
}

class H3Request extends EventEmitter {
  constructor(stream, h3conn, isServer) {
    super();
    this.stream   = stream;
    this.h3       = h3conn;
    this.isServer = isServer;

    this.headers  = {};
    this._realHeaders = {}; 
    
    this.trailers = null;
    this.body     = Buffer.alloc(0);

    this._headersSent     = false;
    this._headersReceived = false;
    this._complete        = false;
    this._isFinalized     = false;
    this._responseHeaders = {};

    this.method    = null;
    this.path      = null;
    this.scheme    = null;
    this.authority = null;
    this.status    = null;

    this._dataChunks = [];
    this._isFlowing  = false;
    this._endPending = false;

    this.on('newListener', (eventName) => {
      if ((eventName === 'data' || eventName === 'end') && !this._isFlowing) {
        this._isFlowing = true;
        process.nextTick(() => this._flushBufferedData());
      }
    });
  }

  get url() { return this.path || '/'; }
  get originalUrl() { return this.path || '/'; }

  _flushBufferedData() {
    if (!this._isFlowing) return;
    while (this._dataChunks.length > 0) {
      this.emit('data', this._dataChunks.shift());
    }
    if (this._endPending && !this._complete) {
      this._complete = true;
      this.emit('end');
    }
  }

  _handleFrame(frame) {
    switch (frame.type) {
      case H3_FRAME.HEADERS:
        this._handleHeaders(frame.payload);
        break;
      case H3_FRAME.DATA:
        this.body = Buffer.concat([this.body, frame.payload]);
        if (this._isFlowing) {
          this.emit('data', frame.payload);
        } else {
          this._dataChunks.push(frame.payload);
        }
        break;
    }
  }

  _handleHeaders(payload) {
    let decoded = [];
    try {
      decoded = this.h3.decoder.decode(payload) || [];
    } catch (err) {
      log.error(`[H3] QPACK Decode Hatası:`, err.message);
    }

    if (!this.headers) this.headers = {};
    if (!this._realHeaders) this._realHeaders = {};

    const hasPseudo = decoded.some(([n]) => String(n).startsWith(':'));
    const isFirstHeaders = !this._headersReceived || hasPseudo;

    if (isFirstHeaders) {
      this._headersReceived = true;

      for (const [name, value] of decoded) {
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

        this.headers[lowerName] = finalVal;
        this._realHeaders[lowerName] = finalVal;

        if (lowerName === ':method') this.method = strValue;
        
        // KESİN ÇÖZÜM: 'url' ve 'originalUrl' GETTER olduğu için TypeError verip 
        // buradaki döngüyü tamamen kilitliyordu! Getter atamaları kaldırıldı.
        if (lowerName === ':path') { 
            this.path = strValue; 
        }
        
        if (lowerName === ':scheme') this.scheme = strValue;
        if (lowerName === ':authority') this.authority = strValue;
        if (lowerName === ':status') this.status = parseInt(strValue, 10);
      }
      this.emit('headers', this.headers);
    } else {
      this.trailers = this.trailers || {};
      for (const [name, value] of decoded) {
        if (name) this.trailers[String(name).toLowerCase()] = String(value ?? '');
      }
      this.emit('trailers', this.trailers);
    }
  }

  _handleEnd() {
    if (this._dataChunks && this._dataChunks.length > 0) {
      for (const chunk of this._dataChunks) {
        this.emit('data', chunk);
      }
      this._dataChunks = [];
    }
    if (!this._complete) {
      this._complete = true;
      this._endPending = false;
      this.emit('end');
    }
  }

  set(key, val) {
    this._responseHeaders[key.toLowerCase()] = String(val);
    return this;
  }

  respond(statusCode, headers = {}, endStream = false) {
    if (this._headersSent) return this;

    const allHeaders = [[':status', String(statusCode)]];
    const mergedHeaders = { ...this._responseHeaders, ...headers };

    for (const [k, v] of Object.entries(mergedHeaders)) {
      allHeaders.push([k.toLowerCase(), String(v)]);
    }

    const { data: encoded } = this.h3.encoder.encode(allHeaders);
    this._headersSent = true;
    this._safeWrite(encodeH3Frame(H3_FRAME.HEADERS, encoded));
    
    if (endStream) {
      this._safeEnd();
    }
    
    return this;
  }

  sendData(data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
    if (buf.length === 0) return this;
    this._safeWrite(encodeH3Frame(H3_FRAME.DATA, buf));
    return this;
  }

  end(data) {
    const hasData = data && data.length > 0;
    
    if (!this._headersSent) {
      this.respond(this.status || 200, {}, !hasData);
    }
    
    if (hasData) {
      this.sendData(data);
      this._safeEnd();
    } else if (this._headersSent) {
      this._safeEnd();
    }
    return this;
  }

  _getQuicImpl() {
    const q = this.h3.quic;
    return (q && q._impl) ? q._impl : q;
  }

  _triggerFlush() {
    const conn = this._getQuicImpl();
    if (conn && typeof conn._flushAll === 'function') {
      setImmediate(() => { try { conn._flushAll(); } catch (e) { log.warn('flush err:', e.message); } });
    }
  }

  _safeWrite(buf) {
    try {
      this.stream.write(buf);
    } catch (e) {
      log.warn('H3 stream write failed:', e.message);
    }
    this._triggerFlush();
  }

  _safeEnd() {
    try {
      if (typeof this.stream.end === 'function') {
        this.stream.end();
      } else if (this.stream.sendFin !== undefined) {
        this.stream.sendFin = true;
      } else {
        log.warn(`[H3] stream ${this.stream.id}: end() metodu ve sendFin bulunamadı`);
      }
    } catch (e) {
      log.warn('H3 stream end failed:', e.message);
    }
    this._triggerFlush();
  }

  write(data) {
    if (!this._headersSent) this.respond(200);
    this.sendData(data);
    return this;
  }

  endRequest(data) {
    if (data) this.write(data);
    this._safeEnd();
    return this;
  }

  json(data) {
    if (!this._headersSent) {
      this.set('content-type', 'application/json; charset=utf-8');
      this.respond(this.status || 200);
    }
    const buf = Buffer.from(JSON.stringify(data));
    this.end(buf);
    return this;
  }
}

module.exports = {
  H3Connection, H3Request, H3_FRAME, H3_SETTINGS, H3_ERROR, UNI_STREAM_TYPE,
  encodeH3Frame, decodeH3Frame, encodeSettings, decodeSettings, buildH3Settings,
};