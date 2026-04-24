'use strict';

const { EventEmitter } = require('events');
const { QpackEncoder, QpackDecoder } = require('./qpack');
const { decodeVarInt, encodeVarInt } = require('../transport/varint');
const { createLogger } = require('../utils/logger');

const log = createLogger('HTTP3');

const H3_FRAME = {
  DATA:         0x00,
  HEADERS:      0x01,
  CANCEL_PUSH:  0x03,
  SETTINGS:     0x04,
  PUSH_PROMISE: 0x05,
  GOAWAY:       0x07,
  MAX_PUSH_ID:  0x0d,
};

const H3_SETTINGS = {
  QPACK_MAX_TABLE_CAPACITY:  0x01,
  MAX_FIELD_SECTION_SIZE:    0x06,
  QPACK_BLOCKED_STREAMS:     0x07,
  ENABLE_CONNECT_PROTOCOL:   0x08,       // RFC 9220
  H3_DATAGRAM:               0x33,       // RFC 9297
  ENABLE_WEBTRANSPORT:       0x2b603742, // draft-ietf-webtrans-http3
};

const H3_ERROR = {
  NO_ERROR:                    0x0100,
  GENERAL_PROTOCOL_ERROR:      0x0101,
  INTERNAL_ERROR:              0x0102,
  STREAM_CREATION_ERROR:       0x0103,
  CLOSED_CRITICAL_STREAM:      0x0104,
  FRAME_UNEXPECTED:            0x0105,
  FRAME_ERROR:                 0x0106,
  EXCESSIVE_LOAD:              0x0107,
  ID_ERROR:                    0x0108,
  SETTINGS_ERROR:              0x0109,
  MISSING_SETTINGS:            0x010a,
  REQUEST_REJECTED:            0x010b,
  REQUEST_CANCELLED:           0x010c,
  REQUEST_INCOMPLETE:          0x010d,
  MESSAGE_ERROR:               0x010e,
  CONNECT_ERROR:               0x010f,
  VERSION_FALLBACK:            0x0110,
};

const UNI_STREAM_TYPE = {
  CONTROL:       0x00,
  PUSH:          0x01,
  QPACK_ENCODER: 0x02,
  QPACK_DECODER: 0x03,
  WEBTRANSPORT:  0x54, 
};

const WT_BIDI_STREAM_PREFIX = 0x41;

function encodeH3Frame(type, payload) {
  return Buffer.concat([
    encodeVarInt(type),
    encodeVarInt(payload.length),
    payload,
  ]);
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
    [H3_SETTINGS.QPACK_MAX_TABLE_CAPACITY]: cfg.qpackMaxTableCapacity ?? 0,
    [H3_SETTINGS.MAX_FIELD_SECTION_SIZE]:   cfg.maxFieldSectionSize   ?? 65536,
    [H3_SETTINGS.QPACK_BLOCKED_STREAMS]:    cfg.qpackBlockedStreams   ?? 0,
  };
  if (cfg.enableWebTransport) {
    s[H3_SETTINGS.ENABLE_CONNECT_PROTOCOL]   = 1;
    s[H3_SETTINGS.H3_DATAGRAM]               = 1;
    // KRİTİK DÜZELTME: Chrome'u çökerten o devasa sayıyı (MAX_SESSIONS) sildik. 
    // Sadece bunu göndermek tüneli açması için yeterlidir.
    s[H3_SETTINGS.ENABLE_WEBTRANSPORT]       = 1;
  }
  return Object.freeze(s);
}

class H3Connection extends EventEmitter {
  constructor(quicConnection, options = {}) {
    super();
    this.quic     = quicConnection;
    this.isServer = options.isServer || false;
    this.encoder = new QpackEncoder({ maxTableCapacity: 0 });
    this.decoder = new QpackDecoder({ maxTableCapacity: 0 });
    this.enableWebTransport = options.enableWebTransport || false;

    this.localSettings = options.settings ? options.settings : buildH3Settings({ enableWebTransport: this.enableWebTransport });
    this.peerSettings = {};
    this.peerSupportsWebTransport = false;

    this.localControlStream  = null;
    this.peerControlStream   = null;
    this.qpackEncoderStream  = null;
    this.qpackDecoderStream  = null;

    this.activeRequests = new Map();
    this.ready     = false;
    this.goawayId  = null;

    this._init();
  }

  _init() {
    if (this.isServer) this.quic.nextUniStreamId = 3;

    this.localControlStream = this.quic.createStream(false);
    const settingsFrame = encodeSettings(this.localSettings);
    this.localControlStream.write(Buffer.concat([Buffer.from([0x00]), settingsFrame]));

    this.qpackEncoderStream = this.quic.createStream(false);
    this.qpackEncoderStream.write(Buffer.from([0x02]));

    this.qpackDecoderStream = this.quic.createStream(false);
    this.qpackDecoderStream.write(Buffer.from([0x03]));

    this.ready = true;
    queueMicrotask(() => this.emit('ready'));

    this.quic.on('stream', (stream) => this._handleStream(stream));

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
    const id = stream.id;
    const isBidi = (id & 0x02) === 0;
    if (isBidi) this._peekBidiStreamType(stream);
    else this._readUniStreamType(stream);
  }

  _peekBidiStreamType(stream) {
    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length === 0) return;
      try {
        const { value: firstVarint, length: fLen } = decodeVarInt(buf, 0);
        if (Number(firstVarint) === WT_BIDI_STREAM_PREFIX) {
          const afterPrefix = buf.subarray(fLen);
          const deliver = (remaining) => {
            try {
              const { value: sid, length: sLen } = decodeVarInt(remaining, 0);
              stream.removeListener('data', onData);
              const payload = remaining.subarray(sLen);
              this.emit('wtBidiStream', Number(sid), stream, payload);
              return true;
            } catch (_) { return false; }
          };
          if (deliver(afterPrefix)) return;
          buf = afterPrefix;
          stream.removeListener('data', onData);
          const onMore = (more) => {
            buf = Buffer.concat([buf, more]);
            if (deliver(buf)) stream.removeListener('data', onMore);
          };
          stream.on('data', onMore);
          return;
        }
        stream.removeListener('data', onData);
        this._handleRequestStream(stream, buf);
      } catch (_) {}
    };
    stream.on('data', onData);
  }

  _readUniStreamType(stream) {
    let typeBuf = Buffer.alloc(0);
    const onData = (chunk) => {
      typeBuf = Buffer.concat([typeBuf, chunk]);
      if (typeBuf.length === 0) return;
      stream.removeListener('data', onData);
      try {
        const { value: streamType, length: tLen } = decodeVarInt(typeBuf, 0);
        const rest = typeBuf.subarray(tLen);
        this._handleUniStream(stream, Number(streamType), rest);
      } catch (e) {}
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
      case UNI_STREAM_TYPE.WEBTRANSPORT:
        this._processWebTransportUniStream(stream, initialData);
        break;
    }
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
                req.emit('error', new Error(`Stream ${streamId} rejected by GOAWAY`));
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
    if (initialData && initialData.length > 0) this.decoder.processEncoderInstruction(initialData);
    stream.on('data', (chunk) => this.decoder.processEncoderInstruction(chunk));
  }

  _handleRequestStream(stream, seed) {
    const request = new H3Request(stream, this, this.isServer);
    this.activeRequests.set(stream.id, request);

    let buf = seed && seed.length > 0 ? Buffer.from(seed) : Buffer.alloc(0);
    let requestEmitted = false;

    const tryEmitRequest = () => {
      if (this.isServer && !requestEmitted && request._headersReceived) {
        requestEmitted = true;
        this.emit('request', request);
      }
    };

    const processBuffer = () => {
      while (buf.length > 0) {
        const frame = decodeH3Frame(buf, 0);
        if (!frame) break;
        buf = buf.subarray(frame.totalLength);
        try { request._handleFrame(frame); } catch (err) {}
        tryEmitRequest();
      }
    };

    if (buf.length > 0) processBuffer();
    stream.on('data', (chunk) => { buf = Buffer.concat([buf, chunk]); processBuffer(); });

    stream.on('end', () => {
      processBuffer();
      if (this.isServer && !requestEmitted) {
        if (!request.method) request.method = 'GET';
        if (!request.path)   request.path   = '/';
        requestEmitted = true;
        this.emit('request', request);
      }
      request._handleEnd();
      this.activeRequests.delete(stream.id);
    });

    stream.on('error', () => this.activeRequests.delete(stream.id));
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

    let responseBuf = Buffer.alloc(0);
    stream.on('data', (chunk) => {
      responseBuf = Buffer.concat([responseBuf, chunk]);
      while (responseBuf.length > 0) {
        const frame = decodeH3Frame(responseBuf, 0);
        if (!frame) break;
        responseBuf = responseBuf.subarray(frame.totalLength);
        req._handleFrame(frame);
      }
    });
    stream.on('end', () => req._handleEnd());
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

    this.headers  = null;
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
  }

  _handleFrame(frame) {
    switch (frame.type) {
      case H3_FRAME.HEADERS:
        this._handleHeaders(frame.payload);
        break;
      case H3_FRAME.DATA:
        this.body = Buffer.concat([this.body, frame.payload]);
        this.emit('data', frame.payload);
        break;
    }
  }

  _handleHeaders(payload) {
    let decoded;
    try { decoded = this.h3.decoder.decode(payload); } catch (err) { decoded = []; }

    if (!this._headersReceived) {
      this._headersReceived = true;
      this.headers = {};
      for (const [name, value] of decoded) {
        switch (name) {
          case ':method':    this.method    = value; break;
          case ':path':      this.path      = value; break;
          case ':scheme':    this.scheme    = value; break;
          case ':authority': this.authority = value; break;
          case ':status':    this.status    = parseInt(value, 10); break;
          default: this.headers[name] = value; break;
        }
      }
      this.emit('headers', this.headers);
    }
  }

  _handleEnd() {
    this._complete = true;
    this.emit('end');
  }

  set(key, val) {
    this._responseHeaders[key.toLowerCase()] = String(val);
    return this;
  }

  respond(statusCode, headers = {}) {
    if (this._headersSent) return this;

    const allHeaders = [[':status', String(statusCode)]];
    const mergedHeaders = { ...this._responseHeaders, ...headers };
    
    for (const [k, v] of Object.entries(mergedHeaders)) {
      allHeaders.push([k.toLowerCase(), String(v)]);
    }

    const { data: encoded } = this.h3.encoder.encode(allHeaders);
    this.stream.write(encodeH3Frame(H3_FRAME.HEADERS, encoded));
    this._headersSent = true;
    return this;
  }

  sendData(data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
    if (buf.length === 0) return this; // Boş frame kalkanı
    this.stream.write(encodeH3Frame(H3_FRAME.DATA, buf));
    return this;
  }

  end(data) {
    if (!this._headersSent) this.respond(200);
    if (data) this.sendData(data);
    this.stream.end();
    return this;
  }

  write(data) {
    if (!this._headersSent) this.respond(200);
    this.sendData(data);
    return this;
  }

  endRequest(data) {
    if (data) this.write(data);
    this.stream.end();
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