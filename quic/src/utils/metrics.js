'use strict';

/**
 * Metrics — in-process structured runtime telemetry for the QUIC / HTTP/3 / WT stack.
 *
 * Design goals:
 * - Zero external deps.
 * - Cheap to update (plain object mutations).
 * - JSON-serializable snapshot for scraping by external exporters.
 * - Attach once to a server / connection / h3 / wt instance and it self-populates.
 *
 * Usage:
 *   const metrics = new Metrics();
 *   metrics.attachServer(quicServer);
 *   metrics.attachConnection(quicConn);
 *   metrics.attachH3(h3Conn);
 *   metrics.attachWt(wtServer);
 *   console.log(metrics.snapshot());
 */

const { EventEmitter } = require('events');

function now() { return Date.now(); }

class Counter {
  constructor() { this.value = 0; }
  add(n = 1) { this.value += n; }
  toJSON() { return this.value; }
}

class Gauge {
  constructor() { this.value = 0; }
  inc(n = 1) { this.value += n; }
  dec(n = 1) { this.value -= n; }
  set(v) { this.value = v; }
  toJSON() { return this.value; }
}

class Histogram {
  // Simple reservoir/summary — keeps count, sum, min, max plus a small ring
  // of recent samples for p50/p95 approximation without sorting the whole set.
  constructor(size = 256) {
    this.count = 0;
    this.sum = 0;
    this.min = null;
    this.max = null;
    this._ring = new Array(size);
    this._idx = 0;
    this._size = size;
  }
  observe(v) {
    this.count++;
    this.sum += v;
    if (this.min === null || v < this.min) this.min = v;
    if (this.max === null || v > this.max) this.max = v;
    this._ring[this._idx % this._size] = v;
    this._idx++;
  }
  _percentiles() {
    const filled = Math.min(this._idx, this._size);
    if (filled === 0) return { p50: null, p95: null };
    const samples = this._ring.slice(0, filled).slice().sort((a, b) => a - b);
    return {
      p50: samples[Math.floor(filled * 0.50)],
      p95: samples[Math.min(filled - 1, Math.floor(filled * 0.95))],
    };
  }
  toJSON() {
    const avg = this.count > 0 ? this.sum / this.count : null;
    return { count: this.count, sum: this.sum, min: this.min, max: this.max, avg, ...this._percentiles() };
  }
}

class Metrics extends EventEmitter {
  constructor() {
    super();
    this.startedAt = now();

    this.connections = {
      opened: new Counter(),
      closed: new Counter(),
      active: new Gauge(),
      handshakeFailed: new Counter(),
      handshakeDurationMs: new Histogram(),
      versionNegotiations: new Counter(),
    };
    this.streams = {
      opened: new Counter(),
      closed: new Counter(),
      reset: new Counter(),
      active: new Gauge(),
    };
    this.protocol = {
      packetsSent: new Counter(),
      packetsReceived: new Counter(),
      bytesSent: new Counter(),
      bytesReceived: new Counter(),
      packetsLost: new Counter(),
      ptoTimeouts: new Counter(),
    };
    this.zeroRtt = {
      accepted: new Counter(),
      rejected: new Counter(),
      replayed: new Counter(),
    };
    this.h3 = {
      requests: new Counter(),
      responses: new Counter(),
      goawaysSent: new Counter(),
      goawaysReceived: new Counter(),
      datagrams: new Counter(),
    };
    this.wt = {
      sessionsOpened: new Counter(),
      sessionsClosed: new Counter(),
      sessionsActive: new Gauge(),
      datagramsSent: new Counter(),
      datagramsReceived: new Counter(),
      bidiStreamsOpened: new Counter(),
      uniStreamsOpened: new Counter(),
    };
  }

  // ===== Attach helpers =====

  attachServer(quicServer) {
    if (!quicServer) return;
    // Hot-path counters: read directly from the server's existing stats on snapshot,
    // but also react to connection events so gauges are correct.
    quicServer.on('connection', (conn) => {
      this.connections.opened.add();
      this.connections.active.inc();
      this.attachConnection(conn);
    });
  }

  attachConnection(conn) {
    if (!conn || conn.__metricsAttached) return;
    conn.__metricsAttached = true;

    const handshakeStart = now();
    let handshakeDone = false;

    conn.on('connected', () => {
      handshakeDone = true;
      this.connections.handshakeDurationMs.observe(now() - handshakeStart);
      this.emit('event', { kind: 'connection.connected', id: conn.scid?.toString('hex') });
    });
    conn.on('closed', () => {
      if (!handshakeDone) this.connections.handshakeFailed.add();
      this.connections.closed.add();
      this.connections.active.dec();
      this.emit('event', { kind: 'connection.closed', id: conn.scid?.toString('hex') });
    });
    conn.on('stream', (stream) => {
      this.streams.opened.add();
      this.streams.active.inc();
      stream.once('end', () => {
        this.streams.closed.add();
        this.streams.active.dec();
      });
      stream.once('reset', () => {
        this.streams.reset.add();
      });
    });
    conn.on('versionNegotiation', () => this.connections.versionNegotiations.add());
    conn.on('packetSent', (size) => { this.protocol.packetsSent.add(); this.protocol.bytesSent.add(size || 0); });
    conn.on('packetReceived', (size) => { this.protocol.packetsReceived.add(); this.protocol.bytesReceived.add(size || 0); });
    conn.on('packetLost', () => this.protocol.packetsLost.add());
    conn.on('ptoTimeout', () => this.protocol.ptoTimeouts.add());
    conn.on('zeroRttAccepted', () => this.zeroRtt.accepted.add());
    conn.on('zeroRttRejected', () => this.zeroRtt.rejected.add());
    conn.on('zeroRttReplayed', () => this.zeroRtt.replayed.add());
  }

  attachH3(h3) {
    if (!h3 || h3.__metricsAttached) return;
    h3.__metricsAttached = true;

    h3.on('request',  () => this.h3.requests.add());
    h3.on('response', () => this.h3.responses.add());
    h3.on('goaway',   () => this.h3.goawaysReceived.add());
    h3.on('goawaySent', () => this.h3.goawaysSent.add());
    h3.on('h3datagram', () => this.h3.datagrams.add());
  }

  attachWt(wtServer) {
    if (!wtServer || wtServer.__metricsAttached) return;
    wtServer.__metricsAttached = true;

    wtServer.on('session', (session) => {
      this.wt.sessionsOpened.add();
      this.wt.sessionsActive.inc();
      session.on('closed', () => {
        this.wt.sessionsClosed.add();
        this.wt.sessionsActive.dec();
      });
      session.on('datagram', () => this.wt.datagramsReceived.add());
      session.on('datagramSent', () => this.wt.datagramsSent.add());
      session.on('bidiStream', () => this.wt.bidiStreamsOpened.add());
      session.on('uniStream', () => this.wt.uniStreamsOpened.add());
    });
  }

  /**
   * Emit a point-in-time JSON snapshot suitable for scraping.
   */
  snapshot() {
    return {
      startedAt: this.startedAt,
      uptimeMs: now() - this.startedAt,
      connections: this.connections,
      streams: this.streams,
      protocol: this.protocol,
      zeroRtt: this.zeroRtt,
      h3: this.h3,
      wt: this.wt,
    };
  }
}

module.exports = { Metrics, Counter, Gauge, Histogram };
