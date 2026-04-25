'use strict';

const dgram = require('dgram');
const { EventEmitter } = require('events');
const { QUIC_VERSION_1 } = require('../constants');
const { generateConnectionId } = require('../crypto/quic-crypto');
const { QuicConnection } = require('../connection/connection');

class QuicClient extends EventEmitter {
  constructor(options = {}) {
    super();

    this.host = options.host || '127.0.0.1';
    this.port = options.port || 4433;
    this.serverName = options.serverName || options.host || 'localhost';
    this.alpn = options.alpn || ['h3'];
    this.version = options.version || QUIC_VERSION_1;
    this.transportParams = options.transportParams || {};
    this.keepaliveInterval = options.keepaliveInterval || 0;
    this.connectTimeout = options.connectTimeout || 15000;

    // mTLS options
    this.cert = options.cert || null;
    this.key = options.key || null;
    this.ca = options.ca || null;
    this.rejectUnauthorized = options.rejectUnauthorized;

    // UDP socket
    this.socket = null;
    this.connection = null;

    // Stats
    this.stats = {
      packetsSent: 0,
      packetsReceived: 0,
    };
  }

  connect() {
    return new Promise((resolve, reject) => {
      let settled = false;
      let timer = null;

      const settle = (fn, arg) => {
        if (settled) return;
        settled = true;
        if (timer) { clearTimeout(timer); timer = null; }
        fn(arg);
      };

      this.socket = dgram.createSocket('udp4');

      this.socket.on('message', (msg) => {
        this.stats.packetsReceived++;
        if (this.connection) this.connection.receivePacket(msg);
      });

      this.socket.on('error', (err) => {
        this.emit('error', err);
        settle(reject, err);
      });

      this.socket.bind(0, () => {
        const scid = generateConnectionId(8);

        this.connection = new QuicConnection({
          isServer: false,
          scid,
          version: this.version,
          serverName: this.serverName,
          alpn: this.alpn,
          transportParams: this.transportParams,
          keepaliveInterval: this.keepaliveInterval,
          clientCert: this.cert,
          clientKey: this.key,
          ca: this.ca,
          rejectUnauthorized: this.rejectUnauthorized,
          sendDatagram: (data) => this._sendRaw(data, this.host, this.port),
          remoteAddress: this.host,
          remotePort: this.port,
        });

        this.connection.on('connected', () => {
          this.emit('connected', this.connection);
          settle(resolve, this.connection);
        });
        this.connection.on('stream', (stream) => this.emit('stream', stream));
        this.connection.on('close',  (code, reason) => this.emit('close', code, reason));
        this.connection.on('closed', () => this.emit('closed'));
        this.connection.on('error',  (err) => {
          this.emit('error', err);
          settle(reject, err);
        });
        this.connection.on('versionNegotiation', (v) => this.emit('versionNegotiation', v));

        if (this.connectTimeout > 0) {
          timer = setTimeout(() => {
            const err = new Error(`QUIC connect timed out after ${this.connectTimeout}ms`);
            try { this.connection && this.connection.close(0, 'connect timeout'); } catch (_) {}
            this.emit('error', err);
            settle(reject, err);
          }, this.connectTimeout);
          if (typeof timer.unref === 'function') timer.unref();
        }

        try {
          this.connection.connect();
        } catch (err) {
          this.emit('error', err);
          settle(reject, err);
        }
      });
    });
  }

  _sendRaw(data, address, port) {
    if (!this.socket) return;
    this.stats.packetsSent++;
    this.socket.send(data, 0, data.length, port, address, (err) => {
      if (err) this.emit('error', err);
    });
  }

  createStream(bidirectional = true) {
    if (!this.connection) throw new Error('Not connected');
    return this.connection.createStream(bidirectional);
  }

  close(errorCode = 0, reason = '') {
    return new Promise((resolve) => {
      if (this.connection) {
        this.connection.close(errorCode, reason);
        this.connection.on('closed', () => {
          if (this.socket) {
            this.socket.close(() => resolve());
          } else {
            resolve();
          }
        });
      } else if (this.socket) {
        this.socket.close(() => resolve());
      } else {
        resolve();
      }
    });
  }
}

module.exports = { QuicClient };