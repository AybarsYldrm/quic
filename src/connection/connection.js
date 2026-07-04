'use strict';

/**
 * Unified Transport
 * Supports HTTP/2 (RFC 7540) and QUIC (RFC 9000) via options.transport
 */

const { EventEmitter } = require('node:events');
const { createLogger } = require('../utils/logger.js');

const log = createLogger('Connection');
const h2Log = createLogger('HTTP2');

const logger = {
  debug: (ns, msg) => h2Log.debug(msg),
  info:  (ns, msg) => h2Log.info(msg),
  warn:  (ns, msg) => h2Log.warn(msg),
  error: (ns, msg) => h2Log.error(msg)
};

// ─────────────────────────────────────────────
// HTTP/2 deps
// ─────────────────────────────────────────────
const { FlowController } = require('./flow-control.js');
const { ServerPush } = require('../push/server-push.js');
const { Http2Stream } = require('../stream/stream.js');
const {
  parseFrame, serializeFrame, buildSettingsFrame, parseSettingsPayload,
  buildHeadersFrame, buildDataFrame, buildWindowUpdateFrame,
  buildRstStreamFrame, buildGoawayFrame, buildPingFrame,
  FrameType, FrameFlags, SettingsId, DEFAULT_SETTINGS, ErrorCode,
} = require('../frame/codec.js');

// ─────────────────────────────────────────────
// QUIC deps
// ─────────────────────────────────────────────
const {
  QUIC_VERSION_1, PACKET_TYPE, FRAME_TYPE, ENCRYPTION_LEVEL,
  TRANSPORT_ERROR, DEFAULT_PARAMS, AEAD_AES_128_GCM, MIN_INITIAL_PACKET_SIZE,
} = require('../constants');
const {
  deriveInitialSecrets, generateConnectionId,
  generateStatelessResetToken, computeNonce,
  aeadEncrypt, aeadDecrypt,
  validateRetryIntegrityTag,
} = require('../crypto/crypto');
const { TLS } = require('../crypto/tls');
const {
  parsePacketHeader, decryptPacket,
  buildLongHeaderPacket, buildShortHeaderPacket,
} = require('../packet/codec');
const { decodeFrames, encodeFrame } = require('../frame/codec');
const { encodeTransportParams, decodeTransportParams } = require('../transport/params');
const { QuicStream, STREAM_STATE, isClientInitiated, isBidirectional } = require('../stream/stream');
const { RecoveryState, PN_SPACE } = require('../recovery/recovery');

// ─────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────
const CONNECTION_PREFACE     = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
const CONNECTION_PREFACE_BUF = Buffer.from(CONNECTION_PREFACE, 'ascii');

const CONN_STATE = {
  IDLE:      'idle',
  HANDSHAKE: 'handshake',
  CONNECTED: 'connected',
  CLOSING:   'closing',
  DRAINING:  'draining',
  CLOSED:    'closed',
};

const MAX_STREAM_CHUNK = 900;

function levelToPnSpace(level) {
  switch (level) {
    case ENCRYPTION_LEVEL.INITIAL:   return PN_SPACE.INITIAL;
    case ENCRYPTION_LEVEL.HANDSHAKE: return PN_SPACE.HANDSHAKE;
    default:                         return PN_SPACE.APPLICATION;
  }
}
function pnSpaceToLevel(pnSpace) {
  switch (pnSpace) {
    case PN_SPACE.INITIAL:   return ENCRYPTION_LEVEL.INITIAL;
    case PN_SPACE.HANDSHAKE: return ENCRYPTION_LEVEL.HANDSHAKE;
    default:                 return ENCRYPTION_LEVEL.ONE_RTT;
  }
}
function levelName(level) {
  switch (level) {
    case ENCRYPTION_LEVEL.INITIAL:   return 'INITIAL';
    case ENCRYPTION_LEVEL.HANDSHAKE: return 'HANDSHAKE';
    case ENCRYPTION_LEVEL.ZERO_RTT:  return '0-RTT';
    case ENCRYPTION_LEVEL.ONE_RTT:   return '1-RTT';
    default:                         return `L${level}`;
  }
}
function _hasAckElicitingFrame(frames) {
  for (const f of frames) {
    if (f.type !== FRAME_TYPE.ACK &&
        f.type !== FRAME_TYPE.ACK_ECN &&
        f.type !== FRAME_TYPE.PADDING &&
        f.type !== FRAME_TYPE.CONNECTION_CLOSE &&
        f.type !== FRAME_TYPE.CONNECTION_CLOSE_APP) return true;
  }
  return false;
}
function dbg(label, ...args) { log.debug(`[${label}]`, ...args); }

// ═══════════════════════════════════════════════════════════════════════════════
// Transport — public facade
// ═══════════════════════════════════════════════════════════════════════════════

class Transport extends EventEmitter {
  constructor(options = {}) {
    super();

    const transport = (options.transport || 'http2').toLowerCase();
    if (transport !== 'http2' && transport !== 'quic') {
      throw new TypeError(`options.transport must be 'http2' or 'quic', got '${transport}'`);
    }

    this.transport = transport;
    this._impl = transport === 'http2'
      ? new Http2Connection(options, this)
      : new QuicConnection(options, this);
  }

  createStream(bidirectional = true) { return this._impl.createStream(bidirectional); }
  sendHeaders(streamId, rawHeaderBlock, endStream = false) {
    if (this.transport === 'http2') {
      this._impl.sendHeaders(streamId, rawHeaderBlock, endStream);
    } else {
      throw new Error('For QUIC, write encoded headers directly to the QUIC stream');
    }
  }
  // Transport sınıfının diğer metodlarının yanına ekle:
  sendData(streamId, data, endStream = false) {
    if (this.transport === 'http2') {
      this._impl._sendData(streamId, data, endStream);
    } else {
      throw new Error('sendData() HTTP/2 only; QUIC stream\'e doğrudan yaz');
    }
  }
  push(associatedStreamId, rawHeaderBlock) { return this._impl.push(associatedStreamId, rawHeaderBlock); }
  ping(callback) { return this._impl.ping(callback); }
  goaway(errorCode) { return this._impl.goaway(errorCode); }
  sendDatagram(data) {
    if (this.transport === 'quic') return this._impl.sendDatagram(data);
    throw new Error('sendDatagram() is only available on QUIC transport');
  }
  close(errorCode = 0, reason = '') { return this._impl.close(errorCode, reason); }
  destroy() { return this._impl.destroy(); }
  connect() {
    if (this.transport === 'quic') return this._impl.connect();
    throw new Error('connect() is only available on QUIC transport');
  }
  receivePacket(buf) {
    if (this.transport === 'quic') return this._impl.receivePacket(buf);
    throw new Error('receivePacket() is only available on QUIC transport');
  }
  get activeStreams() { return this._impl.activeStreams; }
  is0RTT(streamId)  { return this.transport === 'quic' ? this._impl.is0RTT(streamId) : false; }
  get0RTTNonce()    { return this.transport === 'quic' ? this._impl.get0RTTNonce() : null; }
}

// ═══════════════════════════════════════════════════════════════════════════════
// HTTP/2 Connection implementation
// ═══════════════════════════════════════════════════════════════════════════════

class Http2Connection {
  constructor(options = {}, emitter) {
    this._emitter = emitter;

    this.tlsSocket = options.tlsSocket;
    this.isServer  = options.isServer ?? true;

    this.flowControl  = new FlowController(options.initialWindowSize || 65535);
    this.serverPush   = this.isServer ? new ServerPush(this) : null;

    this.streams            = new Map();
    this.nextStreamId       = this.isServer ? 2 : 1;
    this.lastStreamId       = 0;
    this.maxConcurrentStreams = options.maxConcurrentStreams || 100;

    this.localSettings  = { ...DEFAULT_SETTINGS };
    this.remoteSettings = { ...DEFAULT_SETTINGS };

    if (options.maxConcurrentStreams) {
      this.localSettings[SettingsId.MAX_CONCURRENT_STREAMS] = options.maxConcurrentStreams;
    }

    this._prefaceReceived = false;
    this._buffer          = Buffer.alloc(0);
    this._goawaySent      = false;
    this._destroyed       = false;
    this._prefaceBuffer   = Buffer.alloc(0);

    logger.debug('HTTP2', `[INIT] Http2Connection created. Server mode: ${this.isServer}`);

    this.tlsSocket.on('data',  (data) => {
      this._onData(data);
    });
    
    this.tlsSocket.on('end',   () => {
      if (this._destroyed) return;
      logger.info('HTTP2', '[CLOSE] TLS socket ended.');
      this._destroyed = true;
    });
    this.tlsSocket.on('error', (err) => {
      if (this._destroyed) return;
      logger.error('HTTP2', `[ERROR] TLS socket error: ${err.message}`);
      this._destroyed = true;
    });

    if (this.isServer) {
      this._waitingForPreface = true;
      logger.debug('HTTP2', '[STATE] Server is waiting for Client Connection Preface...');
    } else {
      this._waitingForPreface = false;
      this._sendPreface();
    }
  }

  _emit(event, ...args) {
    this._emitter.emit(event, ...args);
  }

  _sendPreface() {
    logger.debug('HTTP2', '[PREFACE] Sending Connection Preface to server.');
    this.tlsSocket.write(CONNECTION_PREFACE_BUF);
    this._sendSettings();
  }

  _sendSettings() {
    const s = {};
    s[SettingsId.MAX_CONCURRENT_STREAMS] = this.localSettings[SettingsId.MAX_CONCURRENT_STREAMS];
    s[SettingsId.INITIAL_WINDOW_SIZE]    = this.localSettings[SettingsId.INITIAL_WINDOW_SIZE];
    s[SettingsId.MAX_FRAME_SIZE]         = this.localSettings[SettingsId.MAX_FRAME_SIZE];
    s[SettingsId.HEADER_TABLE_SIZE]      = this.localSettings[SettingsId.HEADER_TABLE_SIZE];
    
    logger.debug('HTTP2', `[TX] Sending SETTINGS frame: ${JSON.stringify(s)}`);
    this.tlsSocket.write(buildSettingsFrame(s));
  }

  _onData(data) {
    if (this._destroyed) return;

    if (this._waitingForPreface) {
      this._prefaceBuffer = Buffer.concat([this._prefaceBuffer, data]);
      
      if (this._prefaceBuffer.length >= CONNECTION_PREFACE_BUF.length) {
        const preface = this._prefaceBuffer.subarray(0, CONNECTION_PREFACE_BUF.length);
        if (!preface.equals(CONNECTION_PREFACE_BUF)) {
          logger.error('HTTP2', '[FATAL] Invalid connection preface received!');
          this._sendGoaway(ErrorCode.PROTOCOL_ERROR, 'Invalid connection preface');
          return;
        }
        
        logger.info('HTTP2', '[PREFACE] Valid HTTP/2 Connection Preface received.');
        this._prefaceReceived    = true;
        this._waitingForPreface  = false;
        this._sendSettings();
        
        this._buffer = this._prefaceBuffer.subarray(CONNECTION_PREFACE_BUF.length);
        if (this._buffer.length > 0) {
           this._processFrames();
        }
      }
      return;
    }

    this._buffer = Buffer.concat([this._buffer, data]);
    this._processFrames();
  }

  _processFrames() {
    let offset = 0;
    let framesProcessed = 0;

    while (offset < this._buffer.length) {
      const result = parseFrame(this._buffer, offset);
      if (!result) {
        break;
      }
      
      offset += result.consumed;
      framesProcessed++;
      
      try {
        this._handleFrame(result.frame);
      } catch (err) {
        logger.error('HTTP2', `[FATAL] Error handling frame type ${result.frame.type}: ${err.message}`);
      }
    }

    if (offset > 0) this._buffer = this._buffer.subarray(offset);
  }

  _handleFrame(frame) {
    switch (frame.type) {
      case FrameType.SETTINGS:      this._handleSettings(frame);      break;
      case FrameType.HEADERS:       this._handleHeaders(frame);       break;
      case FrameType.DATA:          this._handleData(frame);          break;
      case FrameType.WINDOW_UPDATE: this._handleWindowUpdate(frame);  break;
      case FrameType.RST_STREAM:    this._handleRstStream(frame);     break;
      case FrameType.PING:          this._handlePing(frame);          break;
      case FrameType.GOAWAY:        this._handleGoaway(frame);        break;
      case FrameType.PRIORITY:      this._handlePriority(frame);      break;
      case FrameType.PUSH_PROMISE:  this._handlePushPromise(frame);   break;
      case FrameType.CONTINUATION:  this._handleContinuation(frame);  break;
      default:
        logger.debug('HTTP2', `[WARN] Ignored unknown frame type: ${frame.type}`);
    }
  }

  _handleSettings(frame) {
    if (frame.flags & FrameFlags.ACK) {
      logger.debug('HTTP2', '[SETTINGS] SETTINGS ACK received from peer.');
      return;
    }
    const settings = parseSettingsPayload(frame.payload);

    for (const [id, value] of Object.entries(settings)) {
      this.remoteSettings[Number(id)] = value;
      if (Number(id) === SettingsId.INITIAL_WINDOW_SIZE) {
        const delta = this.flowControl.updateInitialWindowSize(value);
        for (const stream of this.streams.values()) {
          if (stream.sendWindow !== undefined) stream.sendWindow += delta;
        }
      }
    }
    this._emit('remoteSettings', settings);
    this.tlsSocket.write(buildSettingsFrame({}, true));
  }

  _handleHeaders(frame) {
    const streamId = frame.streamId;
    if (streamId === 0) {
      this._sendGoaway(ErrorCode.PROTOCOL_ERROR, 'HEADERS on stream 0');
      return;
    }

    let stream = this.streams.get(streamId);
    let isNewStream = false;

    if (!stream) {
      if (this.isServer && streamId % 2 === 0) {
        this._sendGoaway(ErrorCode.PROTOCOL_ERROR, 'Client sent even stream ID');
        return;
      }
      stream = this._createStream(streamId);
      this.lastStreamId = Math.max(this.lastStreamId, streamId);
      isNewStream = true;
    }

    let headerBlockOffset = 0;
    let padLength = 0;

    if (frame.flags & FrameFlags.PADDED) {
      padLength = frame.payload[headerBlockOffset];
      headerBlockOffset += 1;
    }

    if (frame.flags & FrameFlags.PRIORITY) {
      const depAndExcl      = frame.payload.readUInt32BE(headerBlockOffset);
      stream.exclusive      = !!(depAndExcl & 0x80000000);
      stream.dependency     = depAndExcl & 0x7fffffff;
      stream.weight         = frame.payload[headerBlockOffset + 4] + 1;
      headerBlockOffset    += 5;
    }

    const endHeaders = !!(frame.flags & FrameFlags.END_HEADERS);
    const endStream  = !!(frame.flags & FrameFlags.END_STREAM);
    
    const headerBlock = frame.payload.subarray(headerBlockOffset, frame.payload.length - padLength);

    if (isNewStream) {
      this._emit('stream', stream);
    }

    if (endHeaders) {
      stream.emit('headers', headerBlock, endStream);
    } else {
      stream._headerBuffer = headerBlock;
      stream._endStream    = endStream;
    }
  }

  _handleContinuation(frame) {
    const stream = this.streams.get(frame.streamId);
    if (!stream || !stream._headerBuffer) {
      this._sendGoaway(ErrorCode.PROTOCOL_ERROR, 'Unexpected CONTINUATION');
      return;
    }
    
    stream._headerBuffer = Buffer.concat([stream._headerBuffer, frame.payload]);
    
    if (frame.flags & FrameFlags.END_HEADERS) {
      stream.emit('headers', stream._headerBuffer, stream._endStream);
      delete stream._headerBuffer;
      delete stream._endStream;
    }
  }

  // ── 1. _handleData ──────────────────────────────────────────────────────────
_handleData(frame) {
  const stream = this.streams.get(frame.streamId);
  if (!stream) {
    this._sendRstStream(frame.streamId, ErrorCode.STREAM_CLOSED);
    return;
  }

  const endStream = !!(frame.flags & FrameFlags.END_STREAM);
  let data = frame.payload;

  if (frame.flags & FrameFlags.PADDED) {
    const padLength = data[0];
    data = data.subarray(1, data.length - padLength);
  }

  if (data.length > 0) {
    const increment = this.flowControl.consumeRecvWindow(data.length);
    if (increment > 0) this._sendWindowUpdate(0, increment);
  }

  if (typeof stream.onData === 'function') {
    stream.onData(data, endStream);
  } else {
    if (data.length > 0) stream.emit('data', data);
    if (endStream) stream.emit('end');
  }
}
// ── 2. _handleRstStream ──────────────────────────────────────────────────────
_handleRstStream(frame) {
  const errorCode = frame.payload.readUInt32BE(0);
  logger.info('HTTP2', `[RST_STREAM] Peer reset stream ${frame.streamId} with code ${errorCode}`);
  const stream = this.streams.get(frame.streamId);
  if (stream) {
    if (typeof stream.onReset === 'function') {
      stream.onReset(errorCode);
    } else if (typeof stream.listenerCount === 'function' && stream.listenerCount('error') > 0) {
      // listener yoksa emit('error') Node.js'i crash eder
      stream.emit('error', new Error(`Stream reset with code ${errorCode}`));
    }
    this.streams.delete(frame.streamId);
  }
}

  _handleWindowUpdate(frame) {
    const increment = frame.payload.readUInt32BE(0) & 0x7fffffff;
    if (increment === 0) {
      if (frame.streamId === 0) this._sendGoaway(ErrorCode.PROTOCOL_ERROR, 'Zero window update');
      else this._sendRstStream(frame.streamId, ErrorCode.PROTOCOL_ERROR);
      return;
    }

    if (frame.streamId === 0) {
      this.flowControl.updateConnectionSendWindow(increment);
      this._emit('connectionWindowUpdate');
    } else {
      const stream = this.streams.get(frame.streamId);
      if (stream && typeof stream.updateSendWindow === 'function') {
        stream.updateSendWindow(increment);
      }
    }
  }

  _handlePing(frame) {
    if (frame.flags & FrameFlags.ACK) {
      this._emit('pingAck', frame.payload);
      return;
    }
    this.tlsSocket.write(buildPingFrame(frame.payload, true));
  }

  _handleGoaway(frame) {
    const lastStreamId = frame.payload.readUInt32BE(0) & 0x7fffffff;
    const errorCode    = frame.payload.readUInt32BE(4);
    const debugData    = frame.payload.subarray(8).toString();
    this._emit('goaway', { lastStreamId, errorCode, debugData });
  }

  _handlePriority(frame) {}

  _handlePushPromise(frame) {
    if (!this.isServer) {
      const promisedStreamId = frame.payload.readUInt32BE(0) & 0x7fffffff;
      const rawHeaderBlock = frame.payload.subarray(4);
      this._emit('pushPromise', promisedStreamId, rawHeaderBlock);
    }
  }

  createStream(bidirectional = true) {
    const streamId = this.nextStreamId;
    this.nextStreamId += 2;
    const stream = this._createStream(streamId);
    stream.state = STREAM_STATE.OPEN;
    return stream;
  }

  _createStream(streamId) {
    const stream = new Http2Stream(streamId, this, {
      transport: 'http2',
      sendWindow: this.remoteSettings[SettingsId.INITIAL_WINDOW_SIZE] || 65535
    });
    this.streams.set(streamId, stream);
    stream.on('reset', () => this.streams.delete(streamId));
    return stream;
  }

  sendHeaders(streamId, rawHeaderBlock, endStream) {
    const maxFrameSize = this.remoteSettings[SettingsId.MAX_FRAME_SIZE] || 16384;

    if (rawHeaderBlock.length <= maxFrameSize) {
      this.tlsSocket.write(buildHeadersFrame(streamId, rawHeaderBlock, endStream));
    } else {
      const firstChunk = rawHeaderBlock.subarray(0, maxFrameSize);
      let flags = 0;
      if (endStream) flags |= FrameFlags.END_STREAM;
      this.tlsSocket.write(serializeFrame(FrameType.HEADERS, flags, streamId, firstChunk));

      let offset = maxFrameSize;
      while (offset < rawHeaderBlock.length) {
        const chunk     = rawHeaderBlock.subarray(offset, offset + maxFrameSize);
        offset         += maxFrameSize;
        const contFlags = offset >= rawHeaderBlock.length ? FrameFlags.END_HEADERS : 0;
        this.tlsSocket.write(serializeFrame(FrameType.CONTINUATION, contFlags, streamId, chunk));
      }
    }
  }

  _sendData(streamId, data, endStream) {
    const maxFrameSize = this.remoteSettings[SettingsId.MAX_FRAME_SIZE] || 16384;
    
    if (data.length === 0) {
      this.tlsSocket.write(buildDataFrame(streamId, data, endStream));
      return;
    }

    const stream = this.streams.get(streamId);
    let offset   = 0;

    const sendNextChunk = () => {
      while (offset < data.length) {
        const availableWindow = Math.min(
          Math.max(0, this.flowControl.connectionSendWindow),
          stream && stream.sendWindow !== undefined ? Math.max(0, stream.sendWindow) : Infinity,
        );
        const chunkSize = Math.min(maxFrameSize, data.length - offset, availableWindow);

        if (chunkSize <= 0) {
          let unblocked = false;
          const onUpdate = () => {
            if (unblocked) return;
            unblocked = true;
            this._emitter.removeListener('connectionWindowUpdate', onUpdate);
            if (stream) stream.removeListener('windowUpdate', onUpdate);
            sendNextChunk();
          };
          this._emitter.once('connectionWindowUpdate', onUpdate);
          if (stream) stream.once('windowUpdate', onUpdate);
          return;
        }

        const chunk  = data.subarray(offset, offset + chunkSize);
        offset      += chunkSize;
        const isLast = offset >= data.length;

        this.flowControl.consumeSendWindow(chunkSize);
        if (stream && stream.sendWindow !== undefined) stream.sendWindow -= chunkSize;
        
        this.tlsSocket.write(buildDataFrame(streamId, chunk, isLast && endStream));
      }
    };

    sendNextChunk();
  }

  _sendWindowUpdate(streamId, increment) {
    this.tlsSocket.write(buildWindowUpdateFrame(streamId, increment));
  }

  _sendRstStream(streamId, errorCode) {
    this.tlsSocket.write(buildRstStreamFrame(streamId, errorCode));
  }

  _sendGoaway(errorCode, debugData) {
    if (this._goawaySent) return;
    this._goawaySent = true;
    this.tlsSocket.write(buildGoawayFrame(this.lastStreamId, errorCode, debugData));
  }

  push(associatedStreamId, rawHeaderBlock) {
    if (!this.serverPush) throw new Error('Push not available on client');
    return this.serverPush.push(associatedStreamId, rawHeaderBlock);
  }

  ping(callback) {
    const data = Buffer.alloc(8);
    data.writeBigUInt64BE(BigInt(Date.now()));
    this.tlsSocket.write(buildPingFrame(data));
    if (callback) this._emitter.once('pingAck', callback);
  }

  goaway(errorCode = ErrorCode.NO_ERROR) {
    this._sendGoaway(errorCode, '');
  }

  close(errorCode = 0) {
    this.goaway(errorCode);
  }

  destroy() {
    if (this._destroyed) return;
    this._destroyed = true;
    this.goaway();
    setTimeout(() => {
      if (this.tlsSocket && !this.tlsSocket.destroyed) this.tlsSocket.destroy();
    }, 100);
  }

  connect()            { throw new Error('connect() is QUIC-only'); }
  receivePacket()      { throw new Error('receivePacket() is QUIC-only'); }
  sendDatagram()       { throw new Error('sendDatagram() is QUIC-only'); }
  is0RTT()             { return false; }
  get0RTTNonce()       { return null; }

  get activeStreams() { return this.streams.size; }
}

// ═══════════════════════════════════════════════════════════════════════════════
// QUIC Connection implementation (ORIGINAL)
// ═══════════════════════════════════════════════════════════════════════════════

class QuicConnection {
  constructor(options = {}, emitter) {
    this._emitter = emitter;
    this._label   = (options.isServer ? 'SRV' : 'CLI');

    this.isServer = options.isServer || false;
    this.state    = CONN_STATE.IDLE;
    this.version  = options.version || QUIC_VERSION_1;

    this.scid         = options.scid || generateConnectionId(8);
    this.dcid         = options.dcid || null;
    this.originalDcid = options.originalDcid || null;
    this.peerScid     = null;

    this.ticketStore      = options.ticketStore || null;
    this.zeroRttStreams   = new Set();
    this._lastTicketNonce = null;

    this._sendDatagram = options.sendDatagram || (() => {});
    this.remoteAddress = options.remoteAddress || null;
    this.remotePort    = options.remotePort    || null;

    this.localParams = { ...DEFAULT_PARAMS, ...options.transportParams };
    this.localParams.initialSourceConnectionId = this.scid;
    this.peerParams  = {};

    this.keys = {
      [ENCRYPTION_LEVEL.INITIAL]:   null,
      [ENCRYPTION_LEVEL.HANDSHAKE]: null,
      [ENCRYPTION_LEVEL.ONE_RTT]:   null,
    };

    this.largestRecvPn = {
      [ENCRYPTION_LEVEL.INITIAL]:   -1,
      [ENCRYPTION_LEVEL.HANDSHAKE]: -1,
      [ENCRYPTION_LEVEL.ZERO_RTT]:  -1,
      [ENCRYPTION_LEVEL.ONE_RTT]:   -1,
    };

    this.packetsToAck = {
      [ENCRYPTION_LEVEL.INITIAL]:   [],
      [ENCRYPTION_LEVEL.HANDSHAKE]: [],
      [ENCRYPTION_LEVEL.ONE_RTT]:   [],
    };

    this.pendingFrames = {
      [ENCRYPTION_LEVEL.INITIAL]:   [],
      [ENCRYPTION_LEVEL.HANDSHAKE]: [],
      [ENCRYPTION_LEVEL.ZERO_RTT]:  [],
      [ENCRYPTION_LEVEL.ONE_RTT]:   [],
    };

    if (this.localParams.maxDatagramFrameSize === undefined) {
      this.localParams.maxDatagramFrameSize = 65535;
    }

    const tpBuffer = encodeTransportParams(this.localParams, this.isServer);

    const resumeTicket = (!this.isServer && this.ticketStore && options.serverName)
      ? this.ticketStore.retrieve(options.serverName)
      : null;

    this.tls = new TLS({
      isServer:           this.isServer,
      cert:               options.cert,
      key:                options.key,
      alpn:               options.alpn || ['h3'],
      serverName:         options.serverName || 'localhost',
      transportParams:    tpBuffer,
      enable0rtt:         options.enable0rtt !== undefined ? options.enable0rtt : true,
      ticketKey:          options.ticketKey || null,
      cipherSuites:       options.cipherSuites || undefined,
      requestCert:        options.requestCert || false,
      rejectUnauthorized: options.rejectUnauthorized !== undefined ? options.rejectUnauthorized : false,
      ca:                 options.ca || null,
      clientCert:         options.clientCert || null,
      clientKey:          options.clientKey || null,
      sessionTicket:      resumeTicket,
    });

    this.streams             = new Map();
    this.nextBidiStreamId    = this.isServer ? 1 : 0;
    this.nextUniStreamId     = this.isServer ? 3 : 2;
    this.peerMaxStreamsBidi  = DEFAULT_PARAMS.initialMaxStreamsBidi;
    this.peerMaxStreamsUni   = DEFAULT_PARAMS.initialMaxStreamsUni;

    this.maxSendData = DEFAULT_PARAMS.initialMaxData;
    this.maxRecvData = this.localParams.initialMaxData;
    this.sentData    = 0;
    this.recvData    = 0;

    this.recovery = new RecoveryState();

    this.cryptoSendOffset = {
      [ENCRYPTION_LEVEL.INITIAL]:   0,
      [ENCRYPTION_LEVEL.HANDSHAKE]: 0,
      [ENCRYPTION_LEVEL.ONE_RTT]:   0,
    };

    this.idleTimer       = null;
    this.closeFrame      = null;
    this.keepaliveInterval = options.keepaliveInterval || 0;
    this._keepaliveTimer   = null;

    this._handshakeComplete = false;
    this._flushing          = false;
    this._flushScheduled    = false;
    this._cleaned           = false;
    this._rrIndex           = 0;

    this._setupTLSCallbacks();
    this._setupRecoveryCallbacks();
  }

  _emit(event, ...args) {
    this._emitter.emit(event, ...args);
  }

  _setupTLSCallbacks() {
    this.tls.on('handshakeKeys', (info) => {
      const suite = info.cipher ? info.cipher.aead : 'aes-128-gcm';
      this.keys[ENCRYPTION_LEVEL.HANDSHAKE] = {
        send: { ...(this.isServer ? info.serverKeys : info.clientKeys), suite },
        recv: { ...(this.isServer ? info.clientKeys : info.serverKeys), suite },
      };
    });

    this.tls.on('earlyKeys', ({ keys, suite, ticketNonce }) => {
      this.keys[ENCRYPTION_LEVEL.ZERO_RTT] = { recv: { ...keys, suite } };
      if (ticketNonce) this._lastTicketNonce = ticketNonce;
    });

    this.tls.on('applicationKeys', (info) => {
      const suite = info.cipher ? info.cipher.aead : 'aes-128-gcm';
      this.keys[ENCRYPTION_LEVEL.ONE_RTT] = {
        send: { ...(this.isServer ? info.serverKeys : info.clientKeys), suite },
        recv: { ...(this.isServer ? info.clientKeys : info.serverKeys), suite },
      };
    });

    this.tls.on('peerTransportParams', (buf) => {
      try {
        this.peerParams = decodeTransportParams(buf);
        this._applyPeerParams();
      } catch (e) {
        dbg(this._label, 'Failed to decode peer transport params:', e.message);
      }
    });

    this.tls.on('connected', () => {
      this._handshakeComplete = true;

      if (this.isServer) {
        this.pendingFrames[ENCRYPTION_LEVEL.ONE_RTT].push({ type: FRAME_TYPE.HANDSHAKE_DONE });
        // DÜZELTME: Handshake ve Initial alanlarını burada HEMEN silmiyoruz.
        // İstemcinin "Finished" paketine ACK gönderebilmemiz için onları bekletmemiz gerekiyor.
        // (Aşağıdaki satırları SİLİN)
        // this.keys[ENCRYPTION_LEVEL.INITIAL]   = null;
        // this.keys[ENCRYPTION_LEVEL.HANDSHAKE] = null;
        // this._discardPnSpace(PN_SPACE.INITIAL);
        // this._discardPnSpace(PN_SPACE.HANDSHAKE);
      }

      this.state = CONN_STATE.CONNECTED;
      this._resetIdleTimer();
      this._flushAll();
      this._emit('connected');
    });

    this.tls.on('clientFinished', (info) => {
      this._queueCryptoFrame(info.level, info.data);
      this._flushAll();
    });

    this.tls.on('postHandshakeCrypto', ({ level, data }) => {
      if (this.state !== CONN_STATE.CONNECTED) return;
      this._queueCryptoFrame(level, data);
      this._flushAll();
    });

    this.tls.on('tlsError', (err) => {
      if (this.state === CONN_STATE.CLOSED) return;
      this.state = CONN_STATE.CLOSED;
      this._cleanup();
      this._emit('error', err);
      this._emit('closed');
    });

    this.tls.on('sessionTicket', (ticket) => {
      if (!this.isServer && this.ticketStore && ticket && ticket.serverName) {
        this.ticketStore.store(ticket.serverName, ticket);
      }
      this._emit('sessionTicket', ticket);
    });
  }

  _setupRecoveryCallbacks() {
    this.recovery.on('packetLost', (pnSpace, pn, frames) => {
      const level = pnSpaceToLevel(pnSpace);
      let hasRetransmittable = false;
      for (const frame of frames) {
        if (frame.type === FRAME_TYPE.ACK || frame.type === FRAME_TYPE.PADDING) continue;
        hasRetransmittable = true;
        this.pendingFrames[level].push(frame);
      }
      if (hasRetransmittable) {
        this._flushAll();
      }
    });

    this.recovery.on('packetAcked', (pnSpace, pn, frames) => {
      for (const frame of frames) {
        if (frame.type === FRAME_TYPE.STREAM) {
          const stream = this.streams.get(frame.streamId);
          if (stream) stream._ackData(frame.offset, frame.data.length);
        }
      }
    });

    this.recovery.on('ptoTimeout', (count) => {
      const level = this.keys[ENCRYPTION_LEVEL.ONE_RTT]
        ? ENCRYPTION_LEVEL.ONE_RTT
        : this.keys[ENCRYPTION_LEVEL.HANDSHAKE]
          ? ENCRYPTION_LEVEL.HANDSHAKE
          : ENCRYPTION_LEVEL.INITIAL;
      if (this.keys[level]) {
        this.pendingFrames[level].push({ type: FRAME_TYPE.PING });
        this._flushAll();
      }
    });
  }

  _applyPeerParams() {
    if (this.peerParams.initialMaxData !== undefined)
      this.maxSendData = this.peerParams.initialMaxData;
    if (this.peerParams.initialMaxStreamsBidi !== undefined)
      this.peerMaxStreamsBidi = this.peerParams.initialMaxStreamsBidi;
    if (this.peerParams.initialMaxStreamsUni !== undefined)
      this.peerMaxStreamsUni = this.peerParams.initialMaxStreamsUni;

    if (this.peerParams.maxAckDelay !== undefined) {
      if (typeof this.recovery.setPeerMaxAckDelay === 'function') {
        this.recovery.setPeerMaxAckDelay(this.peerParams.maxAckDelay);
      } else {
        this.recovery.maxAckDelay = this.peerParams.maxAckDelay;
      }
    }
  }

  connect() {
    if (this.state !== CONN_STATE.IDLE) return;
    this.state = CONN_STATE.HANDSHAKE;

    if (!this.dcid) this.dcid = generateConnectionId(8);
    this.originalDcid = Buffer.from(this.dcid);

    const initialSecrets = deriveInitialSecrets(this.dcid, this.version);
    this.keys[ENCRYPTION_LEVEL.INITIAL] = {
      send: { ...initialSecrets.clientKeys, suite: 'aes-128-gcm' },
      recv: { ...initialSecrets.serverKeys, suite: 'aes-128-gcm' },
    };

    const { level, data } = this.tls.generateClientHello();
    this._queueCryptoFrame(level, data);
    this._flushAll();
  }

  _acceptInitial(dcid, scid) {
    this.state        = CONN_STATE.HANDSHAKE;
    this.dcid         = Buffer.from(scid);
    this.originalDcid = Buffer.from(dcid);
    this.localParams.originalDestinationConnectionId = Buffer.from(dcid);
    this.tls.transportParams = encodeTransportParams(this.localParams, true);

    const initialSecrets = deriveInitialSecrets(dcid, this.version);
    this.keys[ENCRYPTION_LEVEL.INITIAL] = {
      send: { ...initialSecrets.serverKeys, suite: 'aes-128-gcm' },
      recv: { ...initialSecrets.clientKeys, suite: 'aes-128-gcm' },
    };
  }

  receivePacket(buf) {
    if (this.state === CONN_STATE.CLOSED) return;
    this._resetIdleTimer();
    this._ackElicitingThisBatch = 0;

    let offset = 0;
    while (offset < buf.length) {
      const remaining = buf.subarray(offset);
      if (remaining.length < 1) break;
      try {
        const consumed = this._processOnePacket(remaining);
        if (consumed <= 0) break;
        offset += consumed;
      } catch (err) {
        break;
      }
    }

    // Bug fixed here: a fatal TLS error handled *inside* the packet-processing
    // try/catch above (e.g. certificate rejection) can synchronously close
    // this connection - via the 'tlsError' -> _cleanup() chain - before this
    // point ever runs. Flushing (or even trying to derive an ACK) afterwards
    // would previously send on a torn-down connection and could throw again,
    // uncaught, since none of this was wrapped in try/catch.
    if (this.state === CONN_STATE.CLOSED) return;

    try {
      const wantsImmediate = this._ackElicitingThisBatch >= 2 || this._hasFlushableData();
      if (wantsImmediate) {
        this._flushAll();
      } else if (this._ackElicitingThisBatch >= 1) {
        this._scheduleDeferredAck();
      } else {
        this._flushAll();
      }
    } catch (err) {
      dbg(this._label, 'post-receive flush failed:', err.message);
    }
  }

  _hasFlushableData() {
    for (const lvl in this.pendingFrames) {
      if (this.pendingFrames[lvl] && this.pendingFrames[lvl].length > 0) return true;
    }
    for (const stream of this.streams.values()) {
      if (stream._hasPendingData && stream._hasPendingData()) return true;
    }
    return false;
  }

  _scheduleDeferredAck() {
    if (this._ackFlushTimer) return;
    const cap   = (this.recovery && this.recovery.maxAckDelay) || 25;
    const delay = Math.max(1, Math.floor(cap / 2));
    this._ackFlushTimer = setTimeout(() => {
      this._ackFlushTimer = null;
      this._flushAll();
    }, delay);
    if (typeof this._ackFlushTimer.unref === 'function') this._ackFlushTimer.unref();
  }

  _processOnePacket(buf) {
    const header = parsePacketHeader(buf);
    if (header.packetType === 'VERSION_NEGOTIATION') {
      this._emit('versionNegotiation', header.versions);
      return buf.length;
    }
    return header.isLong
      ? this._processLongHeaderPacket(buf, header)
      : this._processShortHeaderPacket(buf, header);
  }

  _processLongHeaderPacket(buf, header) {
    let level;
    switch (header.packetType) {
      case PACKET_TYPE.INITIAL:   level = ENCRYPTION_LEVEL.INITIAL;   break;
      case PACKET_TYPE.HANDSHAKE: level = ENCRYPTION_LEVEL.HANDSHAKE; break;
      case PACKET_TYPE.ZERO_RTT:  level = ENCRYPTION_LEVEL.ZERO_RTT;  break;
      case PACKET_TYPE.RETRY:     return this._handleRetry(buf, header);
      default:                    return header.totalLength;
    }

    if (!this.keys[level]) return header.totalLength;

    const packetBuf = buf.subarray(0, header.totalLength);
    const keys      = this.keys[level].recv;

    let result;
    try {
      result = decryptPacket(packetBuf, header, keys, this.largestRecvPn[level]);
    } catch (err) {
      return header.totalLength;
    }

    const { packetNumber, plaintext } = result;
    this.largestRecvPn[level] = Math.max(this.largestRecvPn[level], packetNumber);

    if (!this.isServer && header.packetType === PACKET_TYPE.INITIAL && !this.peerScid) {
      this.peerScid = Buffer.from(header.scid);
      this.dcid     = Buffer.from(header.scid);
    }

    let frames;
    try { frames = decodeFrames(plaintext); }
    catch (err) { return header.totalLength; }

    if (_hasAckElicitingFrame(frames)) {
      const ackLevel = level === ENCRYPTION_LEVEL.ZERO_RTT ? ENCRYPTION_LEVEL.ONE_RTT : level;
      this.packetsToAck[ackLevel].push(packetNumber);
      this._ackElicitingThisBatch = (this._ackElicitingThisBatch || 0) + 1;
    }

    this._processFrames(frames, level);

    if (this.isServer && level === ENCRYPTION_LEVEL.INITIAL &&
        this.tls.state === 'GENERATING_SERVER_HELLO') {
      this._generateServerHandshake();
    }

    return header.totalLength;
  }

  _handleRetry(buf, header) {
    if (this.isServer) return header.totalLength;
    if (this._retryHandled) return header.totalLength;
    if (this.state !== CONN_STATE.HANDSHAKE) return header.totalLength;

    const odcid = this.originalDcid || this.dcid;
    if (!validateRetryIntegrityTag(this.version, odcid, buf.subarray(0, header.totalLength))) {
      return header.totalLength;
    }

    this._retryHandled = true;
    this.dcid         = Buffer.from(header.scid);
    this._retryToken  = Buffer.from(header.retryToken);

    const initialSecrets = deriveInitialSecrets(this.dcid, this.version);
    this.keys[ENCRYPTION_LEVEL.INITIAL] = {
      send: { ...initialSecrets.clientKeys, suite: 'aes-128-gcm' },
      recv: { ...initialSecrets.serverKeys, suite: 'aes-128-gcm' },
    };

    this.pendingFrames[ENCRYPTION_LEVEL.INITIAL]   = [];
    this.packetsToAck[ENCRYPTION_LEVEL.INITIAL]    = [];
    this.largestRecvPn[ENCRYPTION_LEVEL.INITIAL]   = -1;

    if (this.recovery && typeof this.recovery.resetPnSpace === 'function') {
      this.recovery.resetPnSpace(0);
    } else if (this.nextPn) {
      this.nextPn[ENCRYPTION_LEVEL.INITIAL] = 0;
    }

    const { level, data } = this.tls.generateClientHello();
    this._queueCryptoFrame(level, data);
    this._flushAll();
    return header.totalLength;
  }

  _processShortHeaderPacket(buf, header) {
    const level = ENCRYPTION_LEVEL.ONE_RTT;
    if (!this.keys[level]) return buf.length;

    const pnOffset      = 1 + this.scid.length;
    const modifiedHeader = { ...header, pnOffset, isLong: false };
    const keys          = this.keys[level].recv;

    let result;
    try {
      result = decryptPacket(buf, modifiedHeader, keys, this.largestRecvPn[level]);
    } catch (err) {
      return buf.length;
    }

    const { packetNumber, plaintext } = result;
    this.largestRecvPn[level] = Math.max(this.largestRecvPn[level], packetNumber);

    let frames;
    try { frames = decodeFrames(plaintext); }
    catch (err) { return buf.length; }

    if (_hasAckElicitingFrame(frames)) {
      this.packetsToAck[level].push(packetNumber);
      this._ackElicitingThisBatch = (this._ackElicitingThisBatch || 0) + 1;
    }

    this._processFrames(frames, level);
    return buf.length;
  }

  _generateServerHandshake() {
    const result = this.tls.generateServerHello();
    this._queueCryptoFrame(result.serverHello.level, result.serverHello.data);
    this._queueCryptoFrame(result.handshakeData.level, result.handshakeData.data);
  }

  _processFrames(frames, level) {
    for (const frame of frames) {
      switch (frame.type) {
        case FRAME_TYPE.PADDING:
        case FRAME_TYPE.PING:
          break;

        case FRAME_TYPE.ACK:
        case FRAME_TYPE.ACK_ECN: {
          const pnSpace = levelToPnSpace(level);
          this.recovery.onAckReceived(pnSpace, frame);
          break;
        }

        case FRAME_TYPE.CRYPTO:
          this.tls.receiveCryptoData(level, frame.offset, frame.data);
          break;

        case FRAME_TYPE.STREAM:
          this._handleStreamFrame(frame, level);
          break;

        case FRAME_TYPE.MAX_DATA:
          this.maxSendData = Math.max(this.maxSendData, frame.maxData);
          break;

        case FRAME_TYPE.MAX_STREAM_DATA: {
          const stream = this.streams.get(frame.streamId);
          if (stream) stream.maxSendData = Math.max(stream.maxSendData, frame.maxData);
          break;
        }

        case FRAME_TYPE.MAX_STREAMS_BIDI:
          this.peerMaxStreamsBidi = Math.max(this.peerMaxStreamsBidi, frame.maxStreams);
          break;

        case FRAME_TYPE.MAX_STREAMS_UNI:
          this.peerMaxStreamsUni = Math.max(this.peerMaxStreamsUni, frame.maxStreams);
          break;

        case FRAME_TYPE.RESET_STREAM: {
          const s = this.streams.get(frame.streamId);
          if (s) s._handleResetStream(frame.appErrorCode, frame.finalSize);
          break;
        }

        case FRAME_TYPE.STOP_SENDING: {
          const s = this.streams.get(frame.streamId);
          if (s) s._handleStopSending(frame.appErrorCode);
          break;
        }

        case FRAME_TYPE.NEW_CONNECTION_ID:
          this._emit('newConnectionId', frame);
          break;

        case FRAME_TYPE.RETIRE_CONNECTION_ID:
          this._emit('retireConnectionId', frame.sequenceNumber);
          break;

        case FRAME_TYPE.PATH_CHALLENGE:
          this.pendingFrames[level].push({ type: FRAME_TYPE.PATH_RESPONSE, data: frame.data });
          break;

        case FRAME_TYPE.PATH_RESPONSE:
          this._emit('pathResponse', frame.data);
          break;

        case FRAME_TYPE.CONNECTION_CLOSE:
        case FRAME_TYPE.CONNECTION_CLOSE_APP:
          this._handleConnectionClose(frame);
          break;

        case FRAME_TYPE.HANDSHAKE_DONE:
          if (!this.isServer) {
            this._handshakeComplete = true;
            this.state = CONN_STATE.CONNECTED;
            this.keys[ENCRYPTION_LEVEL.INITIAL]   = null;
            this.keys[ENCRYPTION_LEVEL.HANDSHAKE] = null;
            this._discardPnSpace(PN_SPACE.INITIAL);
            this._discardPnSpace(PN_SPACE.HANDSHAKE);
            this._emit('handshakeComplete');
          }
          break;

        case FRAME_TYPE.NEW_TOKEN:
          this._emit('newToken', frame.token);
          break;

        case FRAME_TYPE.DATA_BLOCKED:
        case FRAME_TYPE.STREAM_DATA_BLOCKED:
        case FRAME_TYPE.STREAMS_BLOCKED_BIDI:
        case FRAME_TYPE.STREAMS_BLOCKED_UNI:
          break;

        case FRAME_TYPE.DATAGRAM:
        case FRAME_TYPE.DATAGRAM_WITH_LEN:
          this._emit('datagram', frame.data);
          break;
      }
    }
  }

  _handleStreamFrame(frame, level) {
    let stream = this.streams.get(frame.streamId);
    if (!stream) {
      stream = new QuicStream(frame.streamId, this, {
        maxStreamData: this.isServer
          ? this.localParams.initialMaxStreamDataBidiRemote
          : this.localParams.initialMaxStreamDataBidiLocal,
        initialMaxStreamData: this.peerParams.initialMaxStreamDataBidiLocal || DEFAULT_PARAMS.initialMaxStreamDataBidiLocal,
      });
      this.streams.set(frame.streamId, stream);
      this._emit('stream', stream);
    }
    if (level === ENCRYPTION_LEVEL.ZERO_RTT) this.zeroRttStreams.add(frame.streamId);
    stream._receiveData(frame.offset, frame.data, frame.fin);
    this.recvData += frame.data.length;
  }

  _handleConnectionClose(frame) {
    this.closeFrame = frame;
    this.state      = CONN_STATE.DRAINING;
    this._emit('goaway', { errorCode: frame.errorCode, reasonPhrase: frame.reasonPhrase });

    const pto = this.recovery.smoothedRtt + Math.max(4 * this.recovery.rttVar, 1);
    setTimeout(() => {
      this.state = CONN_STATE.CLOSED;
      this._cleanup();
      this._emit('closed');
    }, 3 * pto);
  }

  createStream(bidirectional = true) {
    let streamId;
    let initialSendWindow = 65535;

    if (bidirectional) {
      streamId = this.nextBidiStreamId;
      this.nextBidiStreamId += 4;
      if (this.peerParams) {
        initialSendWindow = this.isServer
          ? (this.peerParams.initialMaxStreamDataBidiRemote || 65535)
          : (this.peerParams.initialMaxStreamDataBidiLocal  || 65535);
      }
    } else {
      streamId = this.nextUniStreamId;
      this.nextUniStreamId += 4;
      if (this.peerParams) {
        initialSendWindow = this.peerParams.initialMaxStreamDataUni || 65535;
      }
    }

    const stream = new QuicStream(streamId, this, { initialMaxStreamData: initialSendWindow });
    this.streams.set(streamId, stream);
    return stream;
  }

  ping(cb)   {
    if (!this.keys[ENCRYPTION_LEVEL.ONE_RTT]) return;
    this.pendingFrames[ENCRYPTION_LEVEL.ONE_RTT].push({ type: FRAME_TYPE.PING });
    this._flushAll();
    if (cb) setImmediate(cb);
  }
  goaway(errorCode = 0) { this.close(errorCode, ''); }

  _queueCryptoFrame(level, data) {
    const MAX_CHUNK_SIZE = 1000;
    let offset = 0;
    while (offset < data.length) {
      const chunk = data.subarray(offset, offset + MAX_CHUNK_SIZE);
      this.pendingFrames[level].push({
        type:   FRAME_TYPE.CRYPTO,
        offset: this.cryptoSendOffset[level],
        data:   chunk,
      });
      this.cryptoSendOffset[level] += chunk.length;
      offset += MAX_CHUNK_SIZE;
    }
  }

  _flushLevel(level) {
    if (!this.keys[level]) return;

    const pending    = this.pendingFrames[level];
    const acksNeeded = this.packetsToAck[level] && this.packetsToAck[level].length > 0;
    if (pending.length === 0 && !acksNeeded) return;

    let frames = [];
    let currentPayloadLength = 0;

    if (acksNeeded) {
      const ack = this._buildAckFrame(level);
      if (ack) {
        frames.push(ack);
        currentPayloadLength += encodeFrame(ack).length;
      }
    }

    while (pending.length > 0) {
      const nextFrame        = pending[0];
      const encodedNextFrame = encodeFrame(nextFrame);

      if (frames.length > 0 && currentPayloadLength + encodedNextFrame.length > 1150) {
        const payload = Buffer.concat(frames.map(f => encodeFrame(f)));
        this._sendPacket(level, payload, frames);
        frames = [];
        currentPayloadLength = 0;
        continue;
      }

      frames.push(pending.shift());
      currentPayloadLength += encodedNextFrame.length;
    }

    if (frames.length > 0) {
      const payload = Buffer.concat(frames.map(f => encodeFrame(f)));
      this._sendPacket(level, payload, frames);
    }
  }

  _flushAll() {
    if (this._flushing) return;
    this._flushing = true;

    if (this._ackFlushTimer) {
      clearTimeout(this._ackFlushTimer);
      this._ackFlushTimer = null;
    }

    try {
      for (const level of [ENCRYPTION_LEVEL.INITIAL, ENCRYPTION_LEVEL.HANDSHAKE]) {
        this._flushLevel(level);
      }
      this._flushLevel(ENCRYPTION_LEVEL.ONE_RTT);
      this._flushStreams();
    } finally {
      this._flushing = false;
      
      if (this._yieldFlush) {
        this._yieldFlush = false;
        setImmediate(() => this._flushAll());
      }
    }
  }

  _flushStreams() {
    if (!this.keys[ENCRYPTION_LEVEL.ONE_RTT]) return;
    if (this.state !== CONN_STATE.CONNECTED) return;

    const activeStreams = [];
    for (const [id, stream] of this.streams) {
      const fullyClosed = stream.destroyed ||
        (stream._finSent && stream.recvState === STREAM_STATE.READ);
      
      if (fullyClosed) { 
        this.streams.delete(id); 
        continue; 
      }
      
      if (stream.sendBuffer.length > 0 || stream.sendFin) {
        activeStreams.push(stream);
      }
    }
    
    if (activeStreams.length === 0) return;

    let totalPacketsSent = 0;
    const maxPackets     = 50; 

    while (totalPacketsSent < maxPackets) {
      let anyDataThisRound     = false;
      let frames               = [];
      let currentPayloadLength = 0;

      if (this.packetsToAck[ENCRYPTION_LEVEL.ONE_RTT].length > 0) {
        const ack = this._buildAckFrame(ENCRYPTION_LEVEL.ONE_RTT);
        if (ack) { 
          frames.push(ack); 
          currentPayloadLength += encodeFrame(ack).length; 
        }
      }

      for (const stream of activeStreams) {
        if (stream._finSent || stream.destroyed) continue;

        const spaceLeft = Math.max(0, 1150 - currentPayloadLength - 20);
        const maxBytes  = Math.min(MAX_STREAM_CHUNK, spaceLeft);

        if (maxBytes <= 0) {
          if (frames.length > 0) {
            const payload = Buffer.concat(frames.map(f => encodeFrame(f)));
            this._sendPacket(ENCRYPTION_LEVEL.ONE_RTT, payload, frames);
            totalPacketsSent++;
            frames = [];
            currentPayloadLength = 0;
          }
          const newSpace = Math.min(MAX_STREAM_CHUNK, 1150 - 20);
          if (newSpace <= 0) continue;
        }

        const recalcMax = Math.min(MAX_STREAM_CHUNK, Math.max(0, 1150 - currentPayloadLength - 20));
        const pending   = stream._getPendingData(recalcMax);
        if (!pending) continue;
        if (pending.data.length === 0 && !pending.fin) continue;

        anyDataThisRound = true;

        const frame = {
          type:     FRAME_TYPE.STREAM,
          streamId: pending.streamId,
          offset:   pending.offset,
          data:     pending.data,
          fin:      pending.fin,
        };

        this.sentData += pending.data.length;
        frames.push(frame);
        currentPayloadLength += encodeFrame(frame).length;
        
        if (pending.fin) stream._finSent = true;
      }

      if (frames.length > 0) {
        const payload = Buffer.concat(frames.map(f => encodeFrame(f)));
        this._sendPacket(ENCRYPTION_LEVEL.ONE_RTT, payload, frames);
        totalPacketsSent++;
      }

      if (!anyDataThisRound) break;
    }

    if (totalPacketsSent >= maxPackets && this._hasPendingData()) {
      this._yieldFlush = true;
    }
  }

  _sendPacket(level, payload, frames) {
    if (!this.keys[level]) return;

  if (level === ENCRYPTION_LEVEL.INITIAL && !this.isServer) {
    const token     = this._retryToken || Buffer.alloc(0);
    // Long header kesin overhead hesabı:
    // 1 (first) + 4 (ver) + 1 (dcid_len) + dcid + 1 (scid_len) + scid
    // + 1 (token_len) + token + 2 (payload_len varint) + 4 (PN) + 16 (AEAD tag)
    const hdrSize   = 1 + 4 + 1 + this.dcid.length + 1 + this.scid.length
                    + 1 + token.length + 2 + 4 + 16;
    const minPayload = MIN_INITIAL_PACKET_SIZE - hdrSize; // 1200 - ~46 = ~1154
    if (payload.length < minPayload) {
      // PADDING frame = 0x00 byte — RFC 9000 §19.1
      payload = Buffer.concat([payload, Buffer.alloc(minPayload - payload.length, 0x00)]);
    }
  }
    const keys    = this.keys[level].send;
    const pnSpace = levelToPnSpace(level);
    const pn      = this.recovery.nextPn(pnSpace);

    let packet;
    try {
      if (level === ENCRYPTION_LEVEL.ONE_RTT) {
        packet = buildShortHeaderPacket({ dcid: this.dcid, packetNumber: pn, payload, keys });
      } else {
        packet = buildLongHeaderPacket({
          packetType: level === ENCRYPTION_LEVEL.INITIAL ? PACKET_TYPE.INITIAL : PACKET_TYPE.HANDSHAKE,
          version:    this.version,
          dcid:       this.dcid,
          scid:       this.scid,
          token:      level === ENCRYPTION_LEVEL.INITIAL ? (this._retryToken || Buffer.alloc(0)) : undefined,
          packetNumber: pn,
          payload,
          keys,
        });
      }
    } catch (err) {
      return;
    }

    const isAckEliciting = frames.some(f => f.type !== FRAME_TYPE.ACK && f.type !== FRAME_TYPE.PADDING);
    this.recovery.onPacketSent(pnSpace, pn, packet.length, isAckEliciting, frames);
    try {
      // A caller-supplied sendDatagram (e.g. a dgram socket that's already
      // been closed by an error path racing this one) can throw
      // synchronously rather than reporting failure via callback - don't let
      // that surface as an unrelated crash deep in packet-building code.
      this._sendDatagram(packet, this.remoteAddress, this.remotePort);
    } catch (err) {
      dbg(this._label, 'sendDatagram failed:', err.message);
    }
  }

  _buildAckFrame(level) {
    const packets = this.packetsToAck[level];
    if (packets.length === 0) return null;
    packets.sort((a, b) => b - a);

    const ranges = [];
    let start = packets[0], end = packets[0];
    for (let i = 1; i < packets.length; i++) {
      if (packets[i] === start - 1) { start = packets[i]; }
      else { ranges.push({ start, end }); start = packets[i]; end = packets[i]; }
    }
    ranges.push({ start, end });
    this.packetsToAck[level] = [];

    return { type: FRAME_TYPE.ACK, largestAck: ranges[0].end, ackDelay: 0, ranges };
  }

  _discardPnSpace(pnSpace) {
    const space = this.recovery.spaces[pnSpace];
    if (!space) return;

    for (const [, pkt] of space.sentPackets) {
      if (pkt.ackEliciting) this.recovery.bytesInFlight = Math.max(0, this.recovery.bytesInFlight - pkt.size);
    }
    space.sentPackets.clear();
    space.ackElicitingInFlight = 0;
    space.lossTime             = 0;
    this.recovery._setLossDetectionTimer();

    let level = null;
    if (pnSpace === PN_SPACE.INITIAL)   level = ENCRYPTION_LEVEL.INITIAL;
    if (pnSpace === PN_SPACE.HANDSHAKE) level = ENCRYPTION_LEVEL.HANDSHAKE;
    if (level !== null) {
      this.keys[level] = null;
      if (this.packetsToAck[level])  this.packetsToAck[level]  = [];
      if (this.pendingFrames[level]) this.pendingFrames[level]  = [];
      if (this.tls && this.tls.cryptoStreams && this.tls.cryptoStreams[level]) {
        this.tls.cryptoStreams[level].received.clear();
        this.tls.cryptoStreams[level].buffer = Buffer.alloc(0);
      }
    }
  }

  sendDatagram(data) {
    if (this.state !== CONN_STATE.CONNECTED) return false;
    if (!this.keys[ENCRYPTION_LEVEL.ONE_RTT]) return false;
    if (typeof data === 'string') data = Buffer.from(data, 'utf8');
    this.pendingFrames[ENCRYPTION_LEVEL.ONE_RTT].push({ type: FRAME_TYPE.DATAGRAM_WITH_LEN, data });
    this._flushAll();
    return true;
  }

  close(errorCode = 0, reason = '') {
    if (this.state === CONN_STATE.CLOSED || this.state === CONN_STATE.DRAINING) return;
    this.state = CONN_STATE.CLOSING;

    const frame = {
      type: FRAME_TYPE.CONNECTION_CLOSE, errorCode,
      triggerFrameType: 0, reasonPhrase: reason,
    };
    const level = this.keys[ENCRYPTION_LEVEL.ONE_RTT]
      ? ENCRYPTION_LEVEL.ONE_RTT
      : this.keys[ENCRYPTION_LEVEL.HANDSHAKE]
        ? ENCRYPTION_LEVEL.HANDSHAKE
        : ENCRYPTION_LEVEL.INITIAL;

    if (this.keys[level]) {
      const payload = encodeFrame(frame);
      this._sendPacket(level, payload, [frame]);
    }

    const pto = this.recovery.smoothedRtt + Math.max(4 * this.recovery.rttVar, 1);
    setTimeout(() => {
      this.state = CONN_STATE.CLOSED;
      this._cleanup();
      this._emit('closed');
    }, 3 * pto);
  }

  destroy() {
    if (this._cleaned) return;
    this.state = CONN_STATE.CLOSED;
    this._cleanup();      // recovery.destroy() burada → PTO timer anında iptal
    this._emit('closed');
  }

  _resetIdleTimer() {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    const timeout = Math.min(
      this.localParams.maxIdleTimeout,
      this.peerParams.maxIdleTimeout || this.localParams.maxIdleTimeout,
    );
    if (timeout > 0) {
      this.idleTimer = setTimeout(() => {
        dbg(this._label, 'Idle timeout');
        
        // YENİ: Sessizce silmek yerine tarayıcıya CONNECTION_CLOSE gönderiyoruz
        // Böylece tarayıcı sayfayı yenilediğinde eski bağlantıyı beklemek yerine anında YENİ bir QUIC bağlantısı açar.
        if (this.state === CONN_STATE.CONNECTED) {
          this.close(0, 'Idle timeout');
        } else {
          const wasHandshaking = this.state !== CONN_STATE.CONNECTED;
          this.state = CONN_STATE.CLOSED;
          this._cleanup();
          if (wasHandshaking) this._emit('error', new Error('QUIC handshake timed out (idle)'));
          this._emit('closed');
        }
      }, timeout);
    }
    this._resetKeepalive();
  }

  _resetKeepalive() {
    if (this._keepaliveTimer) clearTimeout(this._keepaliveTimer);
    if (!this.keepaliveInterval || this.keepaliveInterval <= 0) return;
    if (this.state !== CONN_STATE.CONNECTED) return;
    this._keepaliveTimer = setTimeout(() => {
      if (this.state !== CONN_STATE.CONNECTED) return;
      if (!this.keys[ENCRYPTION_LEVEL.ONE_RTT]) return;
      this.pendingFrames[ENCRYPTION_LEVEL.ONE_RTT].push({ type: FRAME_TYPE.PING });
      this._flushAll();
      this._emit('keepalive');
    }, this.keepaliveInterval);
    if (this._keepaliveTimer && typeof this._keepaliveTimer.unref === 'function') {
      this._keepaliveTimer.unref();
    }
  }

  _cleanup() {
    if (this._cleaned) return;
    this._cleaned = true;
    if (this.idleTimer)       clearTimeout(this.idleTimer);
    if (this._keepaliveTimer) clearTimeout(this._keepaliveTimer);
    if (this._ackFlushTimer)  { clearTimeout(this._ackFlushTimer); this._ackFlushTimer = null; }
    this.recovery.destroy();
    for (const [, stream] of this.streams) stream.destroy();
    this.streams.clear();
  }

  is0RTT(streamId)  { return this.zeroRttStreams.has(streamId); }
  get0RTTNonce()    { return this._lastTicketNonce ? this._lastTicketNonce.toString('hex') : null; }

  get activeStreams() { return this.streams.size; }
}

module.exports = {
  Transport, 
  Http2Connection, 
  QuicConnection,  
  CONN_STATE,
};