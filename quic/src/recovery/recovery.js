'use strict';

const { EventEmitter } = require('events');

/**
 * Loss Detection & Congestion Control - RFC 9002
 *
 * Implements:
 * - Packet number tracking and ACK processing
 * - RTT estimation (Section 5)
 * - Loss detection timer (Section 6)
 * - NewReno congestion control (Section 7)
 */

const INITIAL_RTT = 333; // ms - RFC 9002 Section 6.2.2
const MAX_DATAGRAM_SIZE = 1200;
const INITIAL_WINDOW = Math.min(10 * MAX_DATAGRAM_SIZE, Math.max(2 * MAX_DATAGRAM_SIZE, 14720));
const MINIMUM_WINDOW = 2 * MAX_DATAGRAM_SIZE;
const LOSS_REDUCTION_FACTOR = 0.5;
const PERSISTENT_CONGESTION_THRESHOLD = 3;

// Packet number spaces
const PN_SPACE = {
  INITIAL:   0,
  HANDSHAKE: 1,
  APPLICATION: 2,
};

class RecoveryState extends EventEmitter {
  constructor() {
    super();

    // RTT estimation
    this.latestRtt = 0;
    this.smoothedRtt = INITIAL_RTT;
    this.rttVar = INITIAL_RTT / 2;
    this.minRtt = Infinity;
    this.firstRttSample = 0;

    // Per-space state
    this.spaces = [
      this._createSpace(), // INITIAL
      this._createSpace(), // HANDSHAKE
      this._createSpace(), // APPLICATION
    ];

    // Congestion control
    this.congestionWindow = INITIAL_WINDOW;
    this.bytesInFlight = 0;
    this.ssthresh = Infinity;
    this.congestionRecoveryStartTime = 0;
    this.ecnCeCounters = [0, 0, 0];

    // Loss detection
    this.lossDetectionTimer = null;
    this.timeOfLastAckEliciting = [0, 0, 0];
    this.ptoCount = 0;

    // Time threshold for loss (Section 6.1.2)
    this.timeThreshold = 9 / 8;
    this.packetThreshold = 3;

    this.maxAckDelay = 25; // ms
  }

  _createSpace() {
    return {
      largestAckedPn: -1,
      sentPackets: new Map(),     // pn -> { time, size, ackEliciting, frames }
      ackElicitingInFlight: 0,
      lossTime: 0,
      nextPn: 0,
    };
  }

  /**
   * Record a sent packet
   */
  onPacketSent(pnSpace, pn, sentBytes, ackEliciting, frames) {
    const space = this.spaces[pnSpace];
    const now = Date.now();

    space.sentPackets.set(pn, {
      time: now,
      size: sentBytes,
      ackEliciting,
      frames,
    });

    if (ackEliciting) {
      this.timeOfLastAckEliciting[pnSpace] = now;
      space.ackElicitingInFlight++;
      this.bytesInFlight += sentBytes;
    }

    this._setLossDetectionTimer();
  }

  /**
   * Process an ACK frame
   */
  onAckReceived(pnSpace, ackFrame) {
    const space = this.spaces[pnSpace];
    const now = Date.now();

    const largestAcked = ackFrame.largestAck;
    if (space.largestAckedPn !== -1 && largestAcked < space.largestAckedPn) {
      return; // Stale ACK
    }

    space.largestAckedPn = Math.max(space.largestAckedPn, largestAcked);

    const newlyAcked = [];

    // Process ACK ranges
    for (const range of ackFrame.ranges) {
      for (let pn = range.start; pn <= range.end; pn++) {
        if (space.sentPackets.has(pn)) {
          newlyAcked.push({ pn, packet: space.sentPackets.get(pn) });
        }
      }
    }

    if (newlyAcked.length === 0) return;

    // Update RTT if largest newly acked
    const largestNewlyAcked = newlyAcked.find(a => a.pn === largestAcked);
    if (largestNewlyAcked) {
      this._updateRtt(now - largestNewlyAcked.packet.time, ackFrame.ackDelay);
    }

    // Remove acked packets
    for (const { pn, packet } of newlyAcked) {
      if (packet.ackEliciting) {
        space.ackElicitingInFlight--;
        this.bytesInFlight -= packet.size;
      }
      space.sentPackets.delete(pn);

      // Notify about acked frames (for stream data ack tracking)
      this.emit('packetAcked', pnSpace, pn, packet.frames);
    }

    // Detect lost packets
    this._detectLostPackets(pnSpace);

    // Congestion control
    for (const { packet } of newlyAcked) {
      this._onPacketAckedCC(packet.size, packet.time);
    }

    this.ptoCount = 0;
    this._setLossDetectionTimer();
  }

  /**
   * RTT Update - RFC 9002 Section 5.3
   */
  _updateRtt(latestRtt, ackDelay) {
    if (this.firstRttSample === 0) {
      this.firstRttSample = Date.now();
      this.minRtt = latestRtt;
      this.smoothedRtt = latestRtt;
      this.rttVar = latestRtt / 2;
      this.latestRtt = latestRtt;
      return;
    }

    this.latestRtt = latestRtt;
    this.minRtt = Math.min(this.minRtt, latestRtt);

    // Adjust for ack delay
    let adjustedRtt = latestRtt;
    if (latestRtt >= this.minRtt + ackDelay) {
      adjustedRtt = latestRtt - Math.min(ackDelay, this.maxAckDelay);
    }

    this.rttVar = 0.75 * this.rttVar + 0.25 * Math.abs(this.smoothedRtt - adjustedRtt);
    this.smoothedRtt = 0.875 * this.smoothedRtt + 0.125 * adjustedRtt;
  }

  /**
   * Loss Detection - RFC 9002 Section 6.1
   */
  _detectLostPackets(pnSpace) {
    const space = this.spaces[pnSpace];
    const now = Date.now();

    const lossDelay = Math.max(
      this.timeThreshold * Math.max(this.latestRtt, this.smoothedRtt),
      1 // at least 1ms
    );

    const lostSentBefore = now - lossDelay;
    space.lossTime = 0;

    const lostPackets = [];

    for (const [pn, packet] of space.sentPackets) {
      if (pn > space.largestAckedPn) continue;

      // Time-based loss
      if (packet.time <= lostSentBefore) {
        lostPackets.push({ pn, packet });
      }
      // Packet number-based loss
      else if (space.largestAckedPn >= pn + this.packetThreshold) {
        lostPackets.push({ pn, packet });
      } else {
        // Set loss time for timer
        const lossTime = packet.time + lossDelay;
        if (space.lossTime === 0 || lossTime < space.lossTime) {
          space.lossTime = lossTime;
        }
      }
    }

    for (const { pn, packet } of lostPackets) {
      space.sentPackets.delete(pn);
      if (packet.ackEliciting) {
        space.ackElicitingInFlight--;
        this.bytesInFlight -= packet.size;
      }
      this._onPacketLostCC(packet.size, packet.time);
      this.emit('packetLost', pnSpace, pn, packet.frames);
    }
  }

  /**
   * Loss Detection Timer - RFC 9002 Section 6.2
   */
  _setLossDetectionTimer() {
    if (this.lossDetectionTimer) {
      clearTimeout(this.lossDetectionTimer);
      this.lossDetectionTimer = null;
    }

    // Check for loss time
    let earliestLossTime = 0;
    let lossSpace = -1;
    for (let i = 0; i < 3; i++) {
      if (this.spaces[i].lossTime > 0) {
        if (earliestLossTime === 0 || this.spaces[i].lossTime < earliestLossTime) {
          earliestLossTime = this.spaces[i].lossTime;
          lossSpace = i;
        }
      }
    }

    if (earliestLossTime > 0) {
      const timeout = Math.max(1, earliestLossTime - Date.now());
      this.lossDetectionTimer = setTimeout(() => {
        this._detectLostPackets(lossSpace);
        this._setLossDetectionTimer();
      }, timeout);
      return;
    }

    // Check for ack-eliciting in flight
    let hasAckEliciting = false;
    for (let i = 0; i < 3; i++) {
      if (this.spaces[i].ackElicitingInFlight > 0) {
        hasAckEliciting = true;
        break;
      }
    }

    if (!hasAckEliciting) return;

    // PTO timeout — RFC 9002 Section 6.2.1
    const pto = this.smoothedRtt + Math.max(4 * this.rttVar, 1) + this.maxAckDelay;
    const ptoTimeout = pto * (1 << this.ptoCount);
    // Floor: at least 10ms to prevent spin-loop on localhost
    const effectivePto = Math.max(ptoTimeout, 10);

    // Find earliest time of last ack-eliciting packet
    let earliest = Infinity;
    for (let i = 0; i < 3; i++) {
      if (this.spaces[i].ackElicitingInFlight > 0 && this.timeOfLastAckEliciting[i] < earliest) {
        earliest = this.timeOfLastAckEliciting[i];
      }
    }

    const timeout = Math.max(1, earliest + effectivePto - Date.now());
    this.lossDetectionTimer = setTimeout(() => {
      this._onPtoTimeout();
    }, timeout);
  }

  _onPtoTimeout() {
    this.ptoCount++;
    this.emit('ptoTimeout', this.ptoCount);
    this._setLossDetectionTimer();
  }

  /**
   * Congestion Control - NewReno (RFC 9002 Section 7)
   */
  _onPacketAckedCC(ackedBytes, sentTime) {
    if (this.congestionWindow < this.ssthresh) {
      // Slow start
      this.congestionWindow += ackedBytes;
    } else {
      // Congestion avoidance
      this.congestionWindow += Math.floor(
        MAX_DATAGRAM_SIZE * ackedBytes / this.congestionWindow
      );
    }
  }

  _onPacketLostCC(lostBytes, sentTime) {
    // Only reduce once per RTT
    if (sentTime <= this.congestionRecoveryStartTime) return;

    this.congestionRecoveryStartTime = Date.now();
    this.ssthresh = Math.max(
      Math.floor(this.congestionWindow * LOSS_REDUCTION_FACTOR),
      MINIMUM_WINDOW
    );
    this.congestionWindow = this.ssthresh;

    this.emit('congestionStateChanged', {
      cwnd: this.congestionWindow,
      ssthresh: this.ssthresh,
      bytesInFlight: this.bytesInFlight,
    });
  }

  /**
   * Check if we can send more data
   */
  canSend() {
    return this.bytesInFlight < this.congestionWindow;
  }

  availableWindow() {
    return Math.max(0, this.congestionWindow - this.bytesInFlight);
  }

  /**
   * Get next packet number for a space
   */
  nextPn(pnSpace) {
    return this.spaces[pnSpace].nextPn++;
  }

  /**
   * Cleanup
   */
  destroy() {
    if (this.lossDetectionTimer) {
      clearTimeout(this.lossDetectionTimer);
    }
    this.removeAllListeners();
  }
}

module.exports = { RecoveryState, PN_SPACE };