'use strict';

const { EventEmitter } = require('events');
const crypto = require('crypto');
const {
  QUIC_VERSION_1, PACKET_TYPE, FRAME_TYPE, ENCRYPTION_LEVEL,
  TRANSPORT_ERROR, DEFAULT_PARAMS, AEAD_AES_128_GCM, MIN_INITIAL_PACKET_SIZE,
} = require('../constants');
const {
  deriveInitialSecrets, generateConnectionId,
  generateStatelessResetToken, computeNonce,
  aeadEncrypt, aeadDecrypt,
  validateRetryIntegrityTag,
} = require('../crypto/quic-crypto');
const { TLSEngine } = require('../crypto/tls-engine');
const {
  parsePacketHeader, decryptPacket,
  buildLongHeaderPacket, buildShortHeaderPacket,
} = require('../packet/codec');
const { decodeFrames, encodeFrame } = require('../frame/codec');
const { encodeTransportParams, decodeTransportParams } = require('../transport/params');
const { QuicStream, STREAM_STATE, isClientInitiated, isBidirectional } = require('../stream/stream');
const { RecoveryState, PN_SPACE } = require('../recovery/recovery');

const { createLogger } = require('../utils/logger');
const log = createLogger('Connection');

const CONN_STATE = {
  IDLE:         'idle',
  HANDSHAKE:    'handshake',
  CONNECTED:    'connected',
  CLOSING:      'closing',
  DRAINING:     'draining',
  CLOSED:       'closed',
};

function debug(side, ...args) {
  log.debug(`[${side}]`, ...args);
}

// Max stream data per packet per stream — enables interleaving
const MAX_STREAM_CHUNK = 900;

class QuicConnection extends EventEmitter {
  constructor(options = {}) {
    super();

    this.isServer = options.isServer || false;
    this.state = CONN_STATE.IDLE;
    this.version = options.version || QUIC_VERSION_1;
    this._label = this.isServer ? 'SRV' : 'CLI';

    // Connection IDs
    this.scid = options.scid || generateConnectionId(8);
    this.dcid = options.dcid || null;
    this.originalDcid = options.originalDcid || null;
    this.peerScid = null;

    // Session Ticket Store for 0-RTT support
    this.ticketStore = options.ticketStore || null;
    this.zeroRttStreams = new Set();
    this._lastTicketNonce = null;

    // UDP transport callback
    this._sendDatagram = options.sendDatagram || (() => {});
    this.remoteAddress = options.remoteAddress || null;
    this.remotePort = options.remotePort || null;

    // Transport parameters
    this.localParams = { ...DEFAULT_PARAMS, ...options.transportParams };
    this.localParams.initialSourceConnectionId = this.scid;
    this.peerParams = {};

    // Encryption keys per level
    this.keys = {
      [ENCRYPTION_LEVEL.INITIAL]: null,
      [ENCRYPTION_LEVEL.HANDSHAKE]: null,
      [ENCRYPTION_LEVEL.ONE_RTT]: null,
    };

    // Largest received PN per level
    this.largestRecvPn = {
      [ENCRYPTION_LEVEL.INITIAL]: -1,
      [ENCRYPTION_LEVEL.HANDSHAKE]: -1,
      [ENCRYPTION_LEVEL.ZERO_RTT]: -1,
      [ENCRYPTION_LEVEL.ONE_RTT]: -1,
    };

    // Packets to ACK per level. 0-RTT and 1-RTT share the application
    // data packet number space (RFC 9001 §5.4.1) so 0-RTT acks ride on
    // 1-RTT packets; we never need a separate ZERO_RTT ack queue.
    this.packetsToAck = {
      [ENCRYPTION_LEVEL.INITIAL]: [],
      [ENCRYPTION_LEVEL.HANDSHAKE]: [],
      [ENCRYPTION_LEVEL.ONE_RTT]: [],
    };

    // Pending frames to send per level
    this.pendingFrames = {
      [ENCRYPTION_LEVEL.INITIAL]: [],
      [ENCRYPTION_LEVEL.HANDSHAKE]: [],
      [ENCRYPTION_LEVEL.ZERO_RTT]: [],
      [ENCRYPTION_LEVEL.ONE_RTT]: [],
    };

    // Ensure datagram frame size is set if not explicitly configured
    // Required for WebTransport compatibility with Chrome
    if (this.localParams.maxDatagramFrameSize === undefined) {
      this.localParams.maxDatagramFrameSize = 65535;
    }

    // Encode transport parameters properly (no manual injection needed)
    const tpBuffer = encodeTransportParams(this.localParams, this.isServer);

    // TLS engine with mTLS and 0-RTT support
    const resumeTicket = (!this.isServer && this.ticketStore && options.serverName)
      ? this.ticketStore.retrieve(options.serverName)
      : null;

    this.tls = new TLSEngine({
      isServer: this.isServer,
      cert: options.cert,
      key: options.key,
      alpn: options.alpn || ['h3'],
      serverName: options.serverName || 'localhost',
      transportParams: tpBuffer,
      // 0-RTT Support
      enable0rtt: options.enable0rtt !== undefined ? options.enable0rtt : true,
      ticketKey: options.ticketKey || null,
      // Cipher Suites
      cipherSuites: options.cipherSuites || undefined,
      // mTLS options
      requestCert: options.requestCert || false,
      rejectUnauthorized: options.rejectUnauthorized !== undefined ? options.rejectUnauthorized : false,
      ca: options.ca || null,
      clientCert: options.clientCert || null,
      clientKey: options.clientKey || null,
      sessionTicket: resumeTicket,
    });

    // Streams
    this.streams = new Map();
    this.nextBidiStreamId = this.isServer ? 1 : 0;
    this.nextUniStreamId = this.isServer ? 3 : 2;
    this.peerMaxStreamsBidi = DEFAULT_PARAMS.initialMaxStreamsBidi;
    this.peerMaxStreamsUni = DEFAULT_PARAMS.initialMaxStreamsUni;

    // Flow control
    this.maxSendData = DEFAULT_PARAMS.initialMaxData;
    this.maxRecvData = this.localParams.initialMaxData;
    this.sentData = 0;
    this.recvData = 0;

    // Recovery
    this.recovery = new RecoveryState();

    // CRYPTO stream offset tracking
    this.cryptoSendOffset = {
      [ENCRYPTION_LEVEL.INITIAL]: 0,
      [ENCRYPTION_LEVEL.HANDSHAKE]: 0,
      [ENCRYPTION_LEVEL.ONE_RTT]: 0,
    };

    // Idle timeout
    this.idleTimer = null;
    this.closeFrame = null;

    // Keepalive
    this.keepaliveInterval = options.keepaliveInterval || 0;
    this._keepaliveTimer   = null;

    // Handshake state
    this._handshakeComplete = false;
    this._flushing = false;
    this._flushScheduled = false;
    this._cleaned = false;

    // Round-robin index for fair stream scheduling
    this._rrIndex = 0;

    this._setupTLSCallbacks();
    this._setupRecoveryCallbacks();
  }

  // ===== TLS Callbacks =====

  _setupTLSCallbacks() {
    this.tls.on('handshakeKeys', (info) => {
      debug(this._label, 'Got handshake keys');
      // Tag the keys with the AEAD suite (e.g. chacha20-poly1305) so the codec picks the right cipher.
      const suite = info.cipher ? info.cipher.aead : 'aes-128-gcm';
      this.keys[ENCRYPTION_LEVEL.HANDSHAKE] = {
        send: { ...(this.isServer ? info.serverKeys : info.clientKeys), suite },
        recv: { ...(this.isServer ? info.clientKeys : info.serverKeys), suite },
      };
    });

    this.tls.on('earlyKeys', ({ keys, suite, ticketNonce }) => {
      // suite is forwarded from tls-engine (chacha20-poly1305 / aes-256-gcm / aes-128-gcm)
      debug(this._label, `0-RTT keys installed (suite=${suite})`);
      this.keys[ENCRYPTION_LEVEL.ZERO_RTT] = {
        recv: { ...keys, suite },
      };
      if (ticketNonce) this._lastTicketNonce = ticketNonce;
    });

    this.tls.on('applicationKeys', (info) => {
      debug(this._label, 'Got application (1-RTT) keys');
      // Tag the keys with the negotiated AEAD suite
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
        debug(this._label, 'Peer transport params applied');
      } catch (e) {
        debug(this._label, 'Failed to decode peer transport params:', e.message);
      }
    });

    this.tls.on('connected', () => {
      debug(this._label, 'TLS connected');
      this._handshakeComplete = true;

      if (this.isServer) {
        this.pendingFrames[ENCRYPTION_LEVEL.ONE_RTT].push(
          { type: FRAME_TYPE.HANDSHAKE_DONE }
        );

        // Clean up handshake keys
        this.keys[ENCRYPTION_LEVEL.INITIAL] = null;
        this.keys[ENCRYPTION_LEVEL.HANDSHAKE] = null;
        this._discardPnSpace(PN_SPACE.INITIAL);
        this._discardPnSpace(PN_SPACE.HANDSHAKE);
      }

      this.state = CONN_STATE.CONNECTED;
      this._resetIdleTimer();
      this._flushAll();
      this.emit('connected');
    });

    this.tls.on('clientFinished', (info) => {
      debug(this._label, 'Sending client Finished');
      this._queueCryptoFrame(info.level, info.data);
      this._flushAll();
    });

    // 0-RTT: TLS event listeners for early data
    this.tls.on('postHandshakeCrypto', ({ level, data }) => {
      debug(this._label, `Enqueuing post-handshake crypto at level ${level}`);
      if (this.state !== CONN_STATE.CONNECTED) return;
      this._queueCryptoFrame(level, data);
      this._flushAll();
    });

    this.tls.on('tlsError', (err) => {
      debug(this._label, `TLS error: ${err.message}`);
      if (this.state === CONN_STATE.CLOSED) return;
      this.state = CONN_STATE.CLOSED;
      this._cleanup();
      this.emit('error', err);
      this.emit('closed');
    });

    this.tls.on('sessionTicket', (ticket) => {
      debug(this._label, 'Received 0-RTT Session Ticket from Server');
      if (!this.isServer && this.ticketStore && ticket && ticket.serverName) {
        this.ticketStore.store(ticket.serverName, ticket);
      }
      this.emit('sessionTicket', ticket);
    });
  }

  // ===== Recovery Callbacks =====

  _setupRecoveryCallbacks() {
    this.recovery.on('packetLost', (pnSpace, pn, frames) => {
      const level = pnSpaceToLevel(pnSpace);
      // Only log + retransmit when the lost packet actually carried
      // application-relevant frames. Pure ACK / PADDING packets count
      // as "lost" in the recovery bookkeeping but there's nothing to
      // resend and nothing the user cares about.
      let hasRetransmittable = false;
      for (const frame of frames) {
        if (frame.type === FRAME_TYPE.ACK || frame.type === FRAME_TYPE.PADDING) continue;
        hasRetransmittable = true;
        this.pendingFrames[level].push(frame);
      }
      if (hasRetransmittable) {
        debug(this._label, `Packet ${pn} lost in space ${pnSpace} (retransmitting)`);
        this._flushAll();
      }
    });

    this.recovery.on('packetAcked', (pnSpace, pn, frames) => {
      for (const frame of frames) {
        if (frame.type === FRAME_TYPE.STREAM) {
          const stream = this.streams.get(frame.streamId);
          if (stream) {
            stream._ackData(frame.offset, frame.data.length);
          }
        }
      }
    });

    this.recovery.on('ptoTimeout', (count) => {
      debug(this._label, `PTO timeout #${count}`);
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
    // Pass the peer's advertised max_ack_delay through the validating
    // setter so PTO never fires before the peer is even allowed to ACK.
    if (this.peerParams.maxAckDelay !== undefined &&
        typeof this.recovery.setPeerMaxAckDelay === 'function') {
      this.recovery.setPeerMaxAckDelay(this.peerParams.maxAckDelay);
    } else if (this.peerParams.maxAckDelay !== undefined) {
      this.recovery.maxAckDelay = this.peerParams.maxAckDelay;
    }
  }

  // ===== Client: Initiate Connection =====

  connect() {
    if (this.state !== CONN_STATE.IDLE) return;
    this.state = CONN_STATE.HANDSHAKE;

    if (!this.dcid) {
      this.dcid = generateConnectionId(8);
    }
    this.originalDcid = Buffer.from(this.dcid);

    const initialSecrets = deriveInitialSecrets(this.dcid, this.version);
    // INITIAL packets MUST use aes-128-gcm per RFC 9001 §5.2.
    this.keys[ENCRYPTION_LEVEL.INITIAL] = {
      send: { ...initialSecrets.clientKeys, suite: 'aes-128-gcm' },
      recv: { ...initialSecrets.serverKeys, suite: 'aes-128-gcm' },
    };

    const { level, data } = this.tls.generateClientHello();
    this._queueCryptoFrame(level, data);
    this._flushAll();
  }

  // ===== Server: Accept Connection =====

  _acceptInitial(dcid, scid) {
    this.state = CONN_STATE.HANDSHAKE;
    this.dcid = Buffer.from(scid);
    this.originalDcid = Buffer.from(dcid);
    this.localParams.originalDestinationConnectionId = Buffer.from(dcid);

    this.tls.transportParams = encodeTransportParams(this.localParams, true);

    const initialSecrets = deriveInitialSecrets(dcid, this.version);
    // INITIAL packets MUST use aes-128-gcm per RFC 9001 §5.2.
    this.keys[ENCRYPTION_LEVEL.INITIAL] = {
      send: { ...initialSecrets.serverKeys, suite: 'aes-128-gcm' },
      recv: { ...initialSecrets.clientKeys, suite: 'aes-128-gcm' },
    };

    debug(this._label, `Accepted initial. DCID=${this.dcid.toString('hex')}, SCID=${this.scid.toString('hex')}`);
  }

  // ===== Packet Processing =====

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
        debug(this._label, `Packet processing error: ${err.message}`);
        break;
      }
    }

    // RFC 9000 §13.2.2: a receiver SHOULD send an ACK frame after
    // receiving at least two ack-eliciting packets, and otherwise MAY
    // delay an ACK by up to max_ack_delay. If we're sending data
    // anyway, the ACK rides on that packet — flush immediately. If
    // not, schedule a deferred ack-only flush so several short bursts
    // are coalesced into one outbound packet.
    const wantsImmediate =
      this._ackElicitingThisBatch >= 2 ||
      this._hasFlushableData();

    if (wantsImmediate) {
      this._flushAll();
    } else if (this._ackElicitingThisBatch >= 1) {
      this._scheduleDeferredAck();
    } else {
      // No ack-eliciting received (e.g., pure ACK from peer); still
      // give pending streams a chance to flush.
      this._flushAll();
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
    // Cap at maxAckDelay (peer-advertised, validated in recovery), half
    // it so the ACK still fits comfortably inside the peer's PTO.
    const cap = (this.recovery && this.recovery.maxAckDelay) || 25;
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
      this.emit('versionNegotiation', header.versions);
      return buf.length;
    }

    if (header.isLong) {
      return this._processLongHeaderPacket(buf, header);
    } else {
      return this._processShortHeaderPacket(buf, header);
    }
  }

  _processLongHeaderPacket(buf, header) {
    let level;
    switch (header.packetType) {
      case PACKET_TYPE.INITIAL:   level = ENCRYPTION_LEVEL.INITIAL; break;
      case PACKET_TYPE.HANDSHAKE: level = ENCRYPTION_LEVEL.HANDSHAKE; break;
      case PACKET_TYPE.ZERO_RTT:  level = ENCRYPTION_LEVEL.ZERO_RTT; break;
      case PACKET_TYPE.RETRY:     return this._handleRetry(buf, header);
      default: return header.totalLength;
    }

    if (!this.keys[level]) {
      debug(this._label, `No keys for level ${level}, skipping packet`);
      return header.totalLength;
    }

    const packetBuf = buf.subarray(0, header.totalLength);
    const keys = this.keys[level].recv; // includes keys.suite

    let result;
    try {
      result = decryptPacket(packetBuf, header, keys, this.largestRecvPn[level]);
    } catch (err) {
      debug(this._label, `Decrypt failed at level ${level}: ${err.message}`);
      return header.totalLength;
    }

    const { packetNumber, plaintext } = result;
    this.largestRecvPn[level] = Math.max(this.largestRecvPn[level], packetNumber);

    if (!this.isServer && header.packetType === PACKET_TYPE.INITIAL && !this.peerScid) {
      this.peerScid = Buffer.from(header.scid);
      this.dcid = Buffer.from(header.scid);
      debug(this._label, `Updated DCID to server SCID: ${this.dcid.toString('hex')}`);
    }

    debug(this._label, `Decrypted ${levelName(level)} packet #${packetNumber}, ${plaintext.length} bytes payload`);

    let frames;
    try {
      frames = decodeFrames(plaintext);
    } catch (err) {
      debug(this._label, `Frame decode error: ${err.message}`);
      return header.totalLength;
    }

    if (_hasAckElicitingFrame(frames)) {
      // 0-RTT and 1-RTT share the application packet number space
      // (RFC 9001 §5.4.1), and we cannot send a 0-RTT-protected ACK
      // (we only have 0-RTT recv keys). Fold 0-RTT ACKs into the
      // 1-RTT queue so they ride on a 1-RTT packet.
      const ackLevel = (level === ENCRYPTION_LEVEL.ZERO_RTT)
        ? ENCRYPTION_LEVEL.ONE_RTT
        : level;
      this.packetsToAck[ackLevel].push(packetNumber);
      this._ackElicitingThisBatch = (this._ackElicitingThisBatch || 0) + 1;
    }

    this._processFrames(frames, level);

    // Server: generate ServerHello after receiving ClientHello
    if (this.isServer && level === ENCRYPTION_LEVEL.INITIAL &&
        this.tls.state === 'GENERATING_SERVER_HELLO') {
      this._generateServerHandshake();
    }

    return header.totalLength;
  }

  // RFC 9000 §17.2.5 / RFC 9001 §5.8: A client MUST accept at most one
  // Retry per connection attempt. We:
  //   1. Validate the integrity tag (using the *original* DCID we sent).
  //   2. Save the new server-chosen connection id and retry token.
  //   3. Re-derive Initial keys with the new DCID.
  //   4. Reset the Initial packet number space and re-emit the
  //      ClientHello with the retry token in the next Initial.
  _handleRetry(buf, header) {
    if (this.isServer) return header.totalLength;
    if (this._retryHandled) {
      debug(this._label, 'Ignoring extra Retry (already processed one)');
      return header.totalLength;
    }
    if (this.state !== CONN_STATE.HANDSHAKE) {
      debug(this._label, 'Ignoring Retry outside handshake state');
      return header.totalLength;
    }

    const odcid = this.originalDcid || this.dcid;
    if (!validateRetryIntegrityTag(this.version, odcid, buf.subarray(0, header.totalLength))) {
      debug(this._label, 'Retry integrity tag invalid, dropping');
      return header.totalLength;
    }

    debug(this._label, `Retry accepted, new DCID=${header.scid.toString('hex')} token=${header.retryToken.length}B`);
    this._retryHandled = true;

    // The server's SCID becomes our new DCID for the rest of the handshake.
    this.dcid = Buffer.from(header.scid);
    this._retryToken = Buffer.from(header.retryToken);

    // Re-derive Initial secrets keyed by the new DCID.
    const initialSecrets = deriveInitialSecrets(this.dcid, this.version);
    this.keys[ENCRYPTION_LEVEL.INITIAL] = {
      send: { ...initialSecrets.clientKeys, suite: 'aes-128-gcm' },
      recv: { ...initialSecrets.serverKeys, suite: 'aes-128-gcm' },
    };

    // Drop any in-flight INITIAL state and re-issue the ClientHello.
    // The TLS transcript stays as-is — generateClientHello() is now
    // idempotent and returns the cached bytes from the first flight,
    // which is what RFC 9001 §5.6 requires.
    this.pendingFrames[ENCRYPTION_LEVEL.INITIAL] = [];
    this.packetsToAck[ENCRYPTION_LEVEL.INITIAL] = [];
    this.largestRecvPn[ENCRYPTION_LEVEL.INITIAL] = -1;
    if (this.recovery && typeof this.recovery.resetPnSpace === 'function') {
      this.recovery.resetPnSpace(0);
    } else {
      // Fallback: reset whatever PN counter the recovery exposes.
      if (this.nextPn) this.nextPn[ENCRYPTION_LEVEL.INITIAL] = 0;
    }

    const { level, data } = this.tls.generateClientHello();
    this._queueCryptoFrame(level, data);
    this._flushAll();
    return header.totalLength;
  }

  _processShortHeaderPacket(buf, header) {
    const level = ENCRYPTION_LEVEL.ONE_RTT;
    if (!this.keys[level]) {
      debug(this._label, 'No 1-RTT keys, dropping short header packet');
      return buf.length;
    }

    const keys = this.keys[level].recv; // includes keys.suite
    const dcidLen = this.scid.length;
    const pnOffset = 1 + dcidLen;

    const modifiedHeader = { ...header, pnOffset, isLong: false };

    let result;
    try {
      result = decryptPacket(buf, modifiedHeader, keys, this.largestRecvPn[level]);
    } catch (err) {
      debug(this._label, `1-RTT decrypt failed: ${err.message}`);
      return buf.length;
    }

    const { packetNumber, plaintext } = result;
    this.largestRecvPn[level] = Math.max(this.largestRecvPn[level], packetNumber);

    debug(this._label, `Decrypted 1-RTT packet #${packetNumber}, ${plaintext.length} bytes`);

    let frames;
    try {
      frames = decodeFrames(plaintext);
    } catch (err) {
      debug(this._label, `Frame decode error in 1-RTT: ${err.message}`);
      return buf.length;
    }

    if (_hasAckElicitingFrame(frames)) {
      this.packetsToAck[level].push(packetNumber);
      this._ackElicitingThisBatch = (this._ackElicitingThisBatch || 0) + 1;
    }

    this._processFrames(frames, level);
    return buf.length;
  }

  _generateServerHandshake() {
    debug(this._label, 'Generating ServerHello + handshake messages');

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
          debug(this._label, `CRYPTO frame at level ${levelName(level)}: offset=${frame.offset}, len=${frame.data.length}`);
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
          this.emit('newConnectionId', frame);
          break;

        case FRAME_TYPE.RETIRE_CONNECTION_ID:
          this.emit('retireConnectionId', frame.sequenceNumber);
          break;

        case FRAME_TYPE.PATH_CHALLENGE:
          this.pendingFrames[level].push({
            type: FRAME_TYPE.PATH_RESPONSE,
            data: frame.data,
          });
          break;

        case FRAME_TYPE.PATH_RESPONSE:
          this.emit('pathResponse', frame.data);
          break;

        case FRAME_TYPE.CONNECTION_CLOSE:
        case FRAME_TYPE.CONNECTION_CLOSE_APP:
          this._handleConnectionClose(frame);
          break;

        case FRAME_TYPE.HANDSHAKE_DONE:
          if (!this.isServer) {
            debug(this._label, 'HANDSHAKE_DONE received');
            this._handshakeComplete = true;
            this.state = CONN_STATE.CONNECTED;
            this.keys[ENCRYPTION_LEVEL.INITIAL] = null;
            this.keys[ENCRYPTION_LEVEL.HANDSHAKE] = null;
            this._discardPnSpace(PN_SPACE.INITIAL);
            this._discardPnSpace(PN_SPACE.HANDSHAKE);
            this.emit('handshakeComplete');
          }
          break;

        case FRAME_TYPE.NEW_TOKEN:
          this.emit('newToken', frame.token);
          break;

        case FRAME_TYPE.DATA_BLOCKED:
        case FRAME_TYPE.STREAM_DATA_BLOCKED:
        case FRAME_TYPE.STREAMS_BLOCKED_BIDI:
        case FRAME_TYPE.STREAMS_BLOCKED_UNI:
          break;

        case FRAME_TYPE.DATAGRAM:
        case FRAME_TYPE.DATAGRAM_WITH_LEN:
          debug(this._label, `Received DATAGRAM frame, length=${frame.data.length}`);
          this.emit('datagram', frame.data);
          break;
      }
    }
  }

// _processFrames passes the encryption level so STREAM frames can be tagged.
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
      debug(this._label, `New stream #${frame.streamId}`);
      this.emit('stream', stream);
    }

    // Mark the stream as 0-RTT-originated so the router can apply replay policy.
    if (level === ENCRYPTION_LEVEL.ZERO_RTT) {
      this.zeroRttStreams.add(frame.streamId);
    }

    stream._receiveData(frame.offset, frame.data, frame.fin);
    this.recvData += frame.data.length;
  }

  _handleConnectionClose(frame) {
    this.closeFrame = frame;
    this.state = CONN_STATE.DRAINING;
    this.emit('close', frame.errorCode, frame.reasonPhrase);

    const pto = this.recovery.smoothedRtt + Math.max(4 * this.recovery.rttVar, 1);
    setTimeout(() => {
      this.state = CONN_STATE.CLOSED;
      this._cleanup();
      this.emit('closed');
    }, 3 * pto);
  }

  // ===== Stream Management =====

// ===== Stream Management =====

  createStream(bidirectional = true) {
    let streamId;
    let initialSendWindow = 65535; // Default 64 KB flow-control window

    if (bidirectional) {
      streamId = this.nextBidiStreamId;
      this.nextBidiStreamId += 4;
      // Bidirectional flow-control window the peer granted us
      if (this.peerParams) {
        initialSendWindow = this.isServer 
          ? (this.peerParams.initialMaxStreamDataBidiRemote || 65535)
          : (this.peerParams.initialMaxStreamDataBidiLocal || 65535);
      }
    } else {
      streamId = this.nextUniStreamId;
      this.nextUniStreamId += 4;
      // Unidirectional (Control / QPACK) flow-control window
      if (this.peerParams) {
        initialSendWindow = this.peerParams.initialMaxStreamDataUni || 65535;
      }
    }

    // Pass the granted window in so the stream can actually emit data
    const stream = new QuicStream(streamId, this, {
      initialMaxStreamData: initialSendWindow
    });
    
    this.streams.set(streamId, stream);
    return stream;
  }
  // ===== Sending =====

  _queueCryptoFrame(level, data) {
    const MAX_CHUNK_SIZE = 1000;
    let offset = 0;

    while (offset < data.length) {
      const chunk = data.subarray(offset, offset + MAX_CHUNK_SIZE);
      const frame = {
        type: FRAME_TYPE.CRYPTO,
        offset: this.cryptoSendOffset[level],
        data: chunk,
      };

      this.cryptoSendOffset[level] += chunk.length;
      this.pendingFrames[level].push(frame);
      offset += MAX_CHUNK_SIZE;
    }
  }

  _flushLevel(level) {
    if (!this.keys[level]) return;

    const pending = this.pendingFrames[level];
    const acksNeeded = this.packetsToAck[level].length > 0;

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
      const nextFrame = pending[0];
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

    // Any pending ACK gets flushed below, so cancel the deferred timer.
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
      if (this._hasPendingData()) {
        setImmediate(() => this._flushAll());
      }
    }
  }

  _hasPendingData() {
    return Object.values(this.pendingFrames).some(p => p.length > 0) ||
           Array.from(this.streams.values()).some(s => s._hasPendingData && s._hasPendingData());
  }

  /**
   * ROUND-ROBIN STREAM FLUSHING — RFC 9000 Multiplexing
   *
   * Collects at most MAX_STREAM_CHUNK bytes from each active stream
   * in round-robin order, packing multiple stream frames into each packet.
   * This interleaving makes browsers show parallel bars in DevTools.
   */
_flushStreams() {
    if (!this.keys[ENCRYPTION_LEVEL.ONE_RTT]) return;
    if (this.state !== CONN_STATE.CONNECTED) return;

    const activeStreams = [];
    // Drop streams from the map only when BOTH directions are done.
    // A stream that sent FIN can still receive data from the peer
    // (half-closed local). Deleting it here breaks the response
    // path on a client that already finished its request body.
    for (const [id, stream] of this.streams) {
      const fullyClosed = stream.destroyed
        || (stream._finSent && stream.recvState === STREAM_STATE.READ);
      if (fullyClosed) {
        this.streams.delete(id);
        continue;
      }
      if (stream.sendBuffer.length > 0 || stream.sendFin) {
        activeStreams.push(stream);
      }
    }

    if (activeStreams.length === 0) return;

    // Round-robin: cycle through all streams until drained
    let totalPacketsSent = 0;
    const maxPackets = 50; // safety limit per flush call

    while (totalPacketsSent < maxPackets) {
      let anyDataThisRound = false;

      let frames = [];
      let currentPayloadLength = 0;

      // Prepend ACK if needed
      if (this.packetsToAck[ENCRYPTION_LEVEL.ONE_RTT].length > 0) {
        const ack = this._buildAckFrame(ENCRYPTION_LEVEL.ONE_RTT);
        if (ack) {
          frames.push(ack);
          currentPayloadLength += encodeFrame(ack).length;
        }
      }

      // One chunk from each active stream per round
      for (const stream of activeStreams) {
        if (stream._finSent || stream.destroyed) continue;

        const spaceLeft = Math.max(0, 1150 - currentPayloadLength - 20);
        const maxBytes = Math.min(MAX_STREAM_CHUNK, spaceLeft);

        if (maxBytes <= 0) {
          // Packet full — send it, start fresh for remaining streams
          if (frames.length > 0) {
            const payload = Buffer.concat(frames.map(f => encodeFrame(f)));
            this._sendPacket(ENCRYPTION_LEVEL.ONE_RTT, payload, frames);
            totalPacketsSent++;
            frames = [];
            currentPayloadLength = 0;
          }
          // Re-check space
          const newSpace = Math.min(MAX_STREAM_CHUNK, 1150 - 20);
          if (newSpace <= 0) continue;
        }

        const recalcMax = Math.min(
          MAX_STREAM_CHUNK,
          Math.max(0, 1150 - currentPayloadLength - 20)
        );

        const pending = stream._getPendingData(recalcMax);
        if (!pending) continue;
        if (pending.data.length === 0 && !pending.fin) continue;

        anyDataThisRound = true;

        const frame = {
          type: FRAME_TYPE.STREAM,
          streamId: pending.streamId,
          offset: pending.offset,
          data: pending.data,
          fin: pending.fin,
        };

        this.sentData += pending.data.length;
        frames.push(frame);
        currentPayloadLength += encodeFrame(frame).length;

        if (pending.fin) {
          stream._finSent = true;
        }
      }

      // Send remaining frames
      if (frames.length > 0) {
        const payload = Buffer.concat(frames.map(f => encodeFrame(f)));
        this._sendPacket(ENCRYPTION_LEVEL.ONE_RTT, payload, frames);
        totalPacketsSent++;
      }

      if (!anyDataThisRound) break;
    }
  }

  _sendResetStream(streamId, errorCode, finalSize) {
    this.pendingFrames[ENCRYPTION_LEVEL.ONE_RTT].push({
      type: FRAME_TYPE.RESET_STREAM,
      streamId,
      appErrorCode: errorCode,
      finalSize,
    });
    this._flushAll();
  }

  _sendPacket(level, payload, frames) {
    if (!this.keys[level]) return;

    const keys = this.keys[level].send; // includes keys.suite
    const pnSpace = levelToPnSpace(level);
    const pn = this.recovery.nextPn(pnSpace);

    let packet;
    try {
      if (level === ENCRYPTION_LEVEL.ONE_RTT) {
        packet = buildShortHeaderPacket({
          dcid: this.dcid,
          packetNumber: pn,
          payload,
          keys,
        });
      } else {
        const packetType = level === ENCRYPTION_LEVEL.INITIAL
          ? PACKET_TYPE.INITIAL
          : PACKET_TYPE.HANDSHAKE;

        packet = buildLongHeaderPacket({
          packetType,
          version: this.version,
          dcid: this.dcid,
          scid: this.scid,
          // INITIAL after a Retry MUST echo the server-issued token
          // (RFC 9000 §17.2.2). Otherwise it's an empty token.
          token: level === ENCRYPTION_LEVEL.INITIAL
            ? (this._retryToken || Buffer.alloc(0))
            : undefined,
          packetNumber: pn,
          payload,
          keys,
        });
      }
    } catch (err) {
      debug(this._label, `Packet build error at level ${levelName(level)}: ${err.message}`);
      return;
    }

    const isAckEliciting = frames.some(f =>
      f.type !== FRAME_TYPE.ACK && f.type !== FRAME_TYPE.PADDING
    );
    this.recovery.onPacketSent(pnSpace, pn, packet.length, isAckEliciting, frames);

    debug(this._label, `Sent ${levelName(level)} packet #${pn}, ${packet.length} bytes, ${frames.length} frames`);

    this._sendDatagram(packet, this.remoteAddress, this.remotePort);
  }

  _buildAckFrame(level) {
    const packets = this.packetsToAck[level];
    if (packets.length === 0) return null;

    packets.sort((a, b) => b - a);

    const ranges = [];
    let start = packets[0];
    let end = packets[0];

    for (let i = 1; i < packets.length; i++) {
      if (packets[i] === start - 1) {
        start = packets[i];
      } else {
        ranges.push({ start, end });
        start = packets[i];
        end = packets[i];
      }
    }
    ranges.push({ start, end });

    this.packetsToAck[level] = [];

    return {
      type: FRAME_TYPE.ACK,
      largestAck: ranges[0].end,
      ackDelay: 0,
      ranges,
    };
  }

  // ===== PN Space Discard (RFC 9002 Section 6.2.2) =====

  _discardPnSpace(pnSpace) {
    const space = this.recovery.spaces[pnSpace];
    if (!space) return;

    for (const [pn, pkt] of space.sentPackets) {
      if (pkt.ackEliciting) {
        this.recovery.bytesInFlight = Math.max(0, this.recovery.bytesInFlight - pkt.size);
      }
    }
    space.sentPackets.clear();
    space.ackElicitingInFlight = 0;
    space.lossTime = 0;

    this.recovery._setLossDetectionTimer();

    // Free per-level state at the same time. Once a PN space is
    // discarded the corresponding encryption level's keys, ack queue,
    // pending frames, and TLS crypto-stream buffers are no longer
    // needed (RFC 9001 §4.9). Releasing them keeps long-lived
    // connections from growing unbounded.
    let level = null;
    if (pnSpace === PN_SPACE.INITIAL) level = ENCRYPTION_LEVEL.INITIAL;
    else if (pnSpace === PN_SPACE.HANDSHAKE) level = ENCRYPTION_LEVEL.HANDSHAKE;
    if (level !== null) {
      this.keys[level] = null;
      if (this.packetsToAck[level]) this.packetsToAck[level] = [];
      if (this.pendingFrames[level]) this.pendingFrames[level] = [];
      if (this.tls && this.tls.cryptoStreams && this.tls.cryptoStreams[level]) {
        this.tls.cryptoStreams[level].received.clear();
        this.tls.cryptoStreams[level].buffer = Buffer.alloc(0);
      }
    }

    debug(this._label, `Discarded PN space ${pnSpace}`);
  }

  // ===== Datagram Sending (RFC 9221) =====

  sendDatagram(data) {
    if (this.state !== CONN_STATE.CONNECTED) return false;
    if (!this.keys[ENCRYPTION_LEVEL.ONE_RTT]) return false;

    if (typeof data === 'string') data = Buffer.from(data, 'utf8');

    this.pendingFrames[ENCRYPTION_LEVEL.ONE_RTT].push({
      type: FRAME_TYPE.DATAGRAM_WITH_LEN,
      data,
    });
    this._flushAll();
    return true;
  }

  // ===== Connection Close =====

  close(errorCode = 0, reason = '') {
    if (this.state === CONN_STATE.CLOSED || this.state === CONN_STATE.DRAINING) return;
    this.state = CONN_STATE.CLOSING;

    const frame = {
      type: FRAME_TYPE.CONNECTION_CLOSE,
      errorCode,
      triggerFrameType: 0,
      reasonPhrase: reason,
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
      this.emit('closed');
    }, 3 * pto);
  }

  // ===== Idle Timer =====

  _resetIdleTimer() {
    if (this.idleTimer) clearTimeout(this.idleTimer);

    const timeout = Math.min(
      this.localParams.maxIdleTimeout,
      this.peerParams.maxIdleTimeout || this.localParams.maxIdleTimeout
    );

    if (timeout > 0) {
      this.idleTimer = setTimeout(() => {
        debug(this._label, 'Idle timeout');
        const wasHandshaking = this.state !== CONN_STATE.CONNECTED;
        this.state = CONN_STATE.CLOSED;
        this._cleanup();
        if (wasHandshaking) {
          this.emit('error', new Error('QUIC handshake timed out (idle)'));
        }
        this.emit('closed');
      }, timeout);
    }
    this._resetKeepalive();
  }

  _resetKeepalive() {
    if (this._keepaliveTimer) clearTimeout(this._keepaliveTimer);
    if (!this.keepaliveInterval || this.keepaliveInterval <= 0) return;
    if (this.state !== CONN_STATE.CONNECTED) return;
    this._keepaliveTimer = setTimeout(() => {
      // Only ping if still connected and 1-RTT keys are installed.
      if (this.state !== CONN_STATE.CONNECTED) return;
      if (!this.keys[ENCRYPTION_LEVEL.ONE_RTT]) return;
      this.pendingFrames[ENCRYPTION_LEVEL.ONE_RTT].push({ type: FRAME_TYPE.PING });
      this._flushAll();
      this.emit('keepalive');
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
    for (const [, stream] of this.streams) {
      stream.destroy();
    }
    this.streams.clear();
  }

  // ===== 0-RTT Helpers =====
  is0RTT(streamId) {
    return this.zeroRttStreams.has(streamId);
  }

  // Returns a stable hex identifier for the resumed ticket, used by
  // the replay cache to key out duplicate 0-RTT flights. Falls back to
  // null when the session was not resumed from a ticket.
  get0RTTNonce() {
    return this._lastTicketNonce
      ? this._lastTicketNonce.toString('hex')
      : null;
  }
}

// ===== Helpers =====

function levelToPnSpace(level) {
  switch (level) {
    case ENCRYPTION_LEVEL.INITIAL: return PN_SPACE.INITIAL;
    case ENCRYPTION_LEVEL.HANDSHAKE: return PN_SPACE.HANDSHAKE;
    default: return PN_SPACE.APPLICATION;
  }
}

function pnSpaceToLevel(pnSpace) {
  switch (pnSpace) {
    case PN_SPACE.INITIAL: return ENCRYPTION_LEVEL.INITIAL;
    case PN_SPACE.HANDSHAKE: return ENCRYPTION_LEVEL.HANDSHAKE;
    default: return ENCRYPTION_LEVEL.ONE_RTT;
  }
}

function levelName(level) {
  switch (level) {
    case ENCRYPTION_LEVEL.INITIAL: return 'INITIAL';
    case ENCRYPTION_LEVEL.HANDSHAKE: return 'HANDSHAKE';
    case ENCRYPTION_LEVEL.ZERO_RTT: return '0-RTT';
    case ENCRYPTION_LEVEL.ONE_RTT: return '1-RTT';
    default: return `L${level}`;
  }
}

function _hasAckElicitingFrame(frames) {
  for (const f of frames) {
    if (f.type !== FRAME_TYPE.ACK &&
        f.type !== FRAME_TYPE.ACK_ECN &&
        f.type !== FRAME_TYPE.PADDING &&
        f.type !== FRAME_TYPE.CONNECTION_CLOSE &&
        f.type !== FRAME_TYPE.CONNECTION_CLOSE_APP) {
      return true;
    }
  }
  return false;
}

module.exports = { QuicConnection, CONN_STATE };
