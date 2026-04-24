'use strict';

const dgram = require('dgram');
const fs = require('fs');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const {
  QUIC_VERSION_1, PACKET_TYPE, MIN_INITIAL_PACKET_SIZE,
  INITIAL_TOKEN_LIFETIME,
} = require('../constants');
const { parsePacketHeader, buildVersionNegotiation } = require('../packet/codec');
const {
  generateConnectionId, generateToken, validateToken,
  computeRetryIntegrityTag,
} = require('../crypto/quic-crypto');
const { QuicConnection } = require('../connection/connection');
const { SessionTicketStore } = require('../crypto/zero-rtt');
const { CertificateValidator } = require('../crypto/cert-validator');
const { createLogger } = require('../utils/logger');

const log = createLogger('Server');

class QuicServer extends EventEmitter {
  constructor(options = {}) {
    super();

    this.port = options.port || 7844;
    this.host = options.host || '0.0.0.0';
    this.cert = options.cert || null;
    this.key = options.key || null;
    this.alpn = options.alpn || ['h3'];
    this.cipherSuites = options.cipherSuites;

    // mTLS options
    this.requestCert = options.requestCert || false;
    this.rejectUnauthorized = options.rejectUnauthorized !== undefined
      ? options.rejectUnauthorized : false;
    this.ca = options.ca || null;

    // Load cert/key from files if paths provided
    if (typeof this.cert === 'string' && this.cert.indexOf('-----') === -1) {
      this.cert = fs.readFileSync(this.cert, 'utf8');
    }
    if (typeof this.key === 'string' && this.key.indexOf('-----') === -1) {
      this.key = fs.readFileSync(this.key, 'utf8');
    }

    // Validate cert/key match at server startup
    if (this.cert && this.key) {
      const keyMatch = CertificateValidator.validateKeyMatch(this.cert, this.key);
      if (!keyMatch.valid) {
        throw new Error(`Server cert/key mismatch: ${keyMatch.error}`);
      }
      log.info('Certificate and private key validated successfully');
    }

    // Transport parameters
    this.transportParams = options.transportParams || {};

    // Connection-level lifecycle tuning forwarded to QuicConnection
    this.keepaliveInterval = options.keepaliveInterval || 0;

    // 0-RTT policy hook: (request) -> boolean. Receives a minimal request
    // descriptor for early-data classification (method/path/safe). Default
    // policy: only safe idempotent methods.
    this.onEarlyData = typeof options.onEarlyData === 'function' ? options.onEarlyData : null;

    // Retry support
    this.requireRetry = options.requireRetry || false;
    this.tokenKey = crypto.randomBytes(16);

    // Supported versions
    this.supportedVersions = [QUIC_VERSION_1];
    this.ticketStore = new SessionTicketStore();

    // Active connections indexed by CID
    this.connections = new Map();

    // UDP socket
    this.socket = null;

    // Stats
    this.stats = {
      packetsReceived: 0,
      packetsSent: 0,
      connectionsAccepted: 0,
    };
  }

  listen(port, host) {
    if (port !== undefined) this.port = port;
    if (host !== undefined) this.host = host;

    return new Promise((resolve, reject) => {
      this.socket = dgram.createSocket('udp4');

      this.socket.on('message', (msg, rinfo) => {
        this.stats.packetsReceived++;
        this._handleDatagram(msg, rinfo);
      });

      this.socket.on('error', (err) => {
        this.emit('error', err);
        reject(err);
      });

      this.socket.bind(this.port, this.host, () => {
        const addr = this.socket.address();
        this.port = addr.port;
        log.info(`QUIC server listening on ${addr.address}:${addr.port}`);
        this.emit('listening', addr);
        resolve(addr);
      });
    });
  }

  _handleDatagram(buf, rinfo) {
    try {
      if (buf.length < 1) return;

      const firstByte = buf[0];
      const isLong = (firstByte & 0x80) !== 0;

      if (isLong) {
        const header = parsePacketHeader(buf);

        // Check existing connection
        const conn = this._findConnection(header.dcid);
        if (conn) {
          conn.remoteAddress = rinfo.address;
          conn.remotePort = rinfo.port;
          conn.receivePacket(buf);
          return;
        }

        // New connection - must be Initial
        if (header.packetType !== PACKET_TYPE.INITIAL) return;

        // Version check
        if (!this.supportedVersions.includes(header.version)) {
          const vnPacket = buildVersionNegotiation(
            header.scid, header.dcid, this.supportedVersions
          );
          this._sendRaw(vnPacket, rinfo.address, rinfo.port);
          return;
        }

        // Minimum size check (RFC 9000 Section 14.1)
        if (buf.length < MIN_INITIAL_PACKET_SIZE) return;

        // Retry handling
        if (this.requireRetry && (!header.token || header.token.length === 0)) {
          this._sendRetry(header, rinfo);
          return;
        }

        // Validate token if present
        if (header.token && header.token.length > 0) {
          const tokenResult = validateToken(
            this.tokenKey, header.token,
            rinfo.address, rinfo.port,
            INITIAL_TOKEN_LIFETIME
          );
          if (!tokenResult) {
            if (this.requireRetry) {
              this._sendRetry(header, rinfo);
              return;
            }
          }
        }

        this._acceptConnection(buf, header, rinfo);
      } else {
        // Short header (1-RTT): extract DCID by trying known CID lengths
        // Server CIDs are 8 bytes by default
        const conn = this._findConnectionByShortHeader(buf);
        if (conn) {
          conn.remoteAddress = rinfo.address;
          conn.remotePort = rinfo.port;
          conn.receivePacket(buf);
        }
        // Drop if no matching connection found
      }
    } catch (err) {
      this.emit('error', err);
    }
  }

  _findConnectionByShortHeader(buf) {
    // Try to match DCID from short header against known server CIDs.
    // Short header format: firstByte(1) + DCID(N) + PN(1-4) + payload
    // We know our CID length (8 bytes), so extract and lookup.
    if (buf.length < 9) return null; // 1 + 8 minimum
    const dcid = buf.subarray(1, 9); // 8-byte CID
    return this._findConnection(dcid);
  }

  _findConnection(dcid) {
    if (!dcid) return null;
    const key = dcid.toString('hex');
    return this.connections.get(key) || null;
  }

  _acceptConnection(buf, header, rinfo) {
    const serverCid = generateConnectionId(8);

    const conn = new QuicConnection({
      isServer: true,
      scid: serverCid,
      dcid: header.scid,
      originalDcid: header.dcid,
      version: header.version,
      cert: this.cert,
      key: this.key,
      alpn: this.alpn,
      cipherSuites: this.cipherSuites,
      transportParams: this.transportParams,
      ticketStore: this.ticketStore,
      keepaliveInterval: this.keepaliveInterval,
      // mTLS options
      requestCert: this.requestCert,
      rejectUnauthorized: this.rejectUnauthorized,
      ca: this.ca,
      sendDatagram: (data, addr, port) => {
        this._sendRaw(data, addr, port);
      },
      remoteAddress: rinfo.address,
      remotePort: rinfo.port,
    });

    // Index by server CID
    this.connections.set(serverCid.toString('hex'), conn);

    // Also index by original DCID for Initial packets
    this.connections.set(header.dcid.toString('hex'), conn);

    conn._acceptInitial(header.dcid, header.scid);

    conn.on('connected', () => {
      this.stats.connectionsAccepted++;
      log.info(`Connection established from ${rinfo.address}:${rinfo.port}`);
      this.emit('connection', conn);
    });

    conn.on('closed', () => {
      this.connections.delete(serverCid.toString('hex'));
      this.connections.delete(header.dcid.toString('hex'));
    });

    conn.on('error', (err) => {
      this.emit('connectionError', err, conn);
    });

    // Process the Initial packet
    conn.receivePacket(buf);
  }

  _sendRetry(header, rinfo) {
    const newScid = generateConnectionId(8);
    const token = generateToken(
      this.tokenKey, header.dcid,
      rinfo.address, rinfo.port
    );

    // Build Retry packet (RFC 9000 Section 17.2.5)
    const parts = [];

    // First byte: long header, Retry type
    const firstByte = 0xc0 | (PACKET_TYPE.RETRY << 4) | (0x0f); // unused bits random
    parts.push(Buffer.from([firstByte]));

    // Version
    const vBuf = Buffer.alloc(4);
    vBuf.writeUInt32BE(header.version, 0);
    parts.push(vBuf);

    // DCID (client's SCID)
    parts.push(Buffer.from([header.scid.length]));
    parts.push(header.scid);

    // SCID (new server CID)
    parts.push(Buffer.from([newScid.length]));
    parts.push(newScid);

    // Token
    parts.push(token);

    const retryWithoutTag = Buffer.concat(parts);

    // Compute integrity tag
    const integrityTag = computeRetryIntegrityTag(
      header.version, header.dcid, retryWithoutTag
    );

    const retryPacket = Buffer.concat([retryWithoutTag, integrityTag]);
    this._sendRaw(retryPacket, rinfo.address, rinfo.port);
  }

  _sendRaw(data, address, port) {
    if (!this.socket) return;
    this.stats.packetsSent++;
    this.socket.send(data, 0, data.length, port, address, (err) => {
      if (err) this.emit('error', err);
    });
  }

  close() {
    return new Promise((resolve) => {
      // Close all connections
      for (const [, conn] of this.connections) {
        conn.close();
      }

      if (this.socket) {
        this.socket.close(() => {
          this.emit('close');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }
}

module.exports = { QuicServer };