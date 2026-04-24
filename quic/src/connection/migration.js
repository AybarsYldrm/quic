'use strict';

/**
 * Connection Migration - RFC 9000 Section 9
 *
 * QUIC connections survive changes in the client's IP address or port.
 * Migration is validated using PATH_CHALLENGE/PATH_RESPONSE probing.
 *
 * Types of migration:
 *   1. NAT rebinding (port change, same IP)
 *   2. Network switch (IP change, e.g., WiFi -> cellular)
 *   3. Intentional migration (client actively moves)
 *
 * Validation flow:
 *   1. Peer sends packet from new address
 *   2. Endpoint sends PATH_CHALLENGE to new address
 *   3. Peer responds with PATH_RESPONSE
 *   4. If valid, endpoint migrates to new path
 *   5. Endpoint MAY probe old path to detect NAT rebinding vs real migration
 */

const crypto = require('crypto');
const { EventEmitter } = require('events');
const { FRAME_TYPE } = require('../constants');

// Path states
const PATH_STATE = {
  UNKNOWN:    'unknown',
  VALIDATING: 'validating',
  VALIDATED:  'validated',
  FAILED:     'failed',
};

class PathValidator extends EventEmitter {
  constructor(options = {}) {
    super();

    // Current validated path
    this.currentPath = {
      remoteAddress: options.remoteAddress || null,
      remotePort: options.remotePort || null,
      state: PATH_STATE.VALIDATED,
      localAddress: options.localAddress || null,
    };

    // Pending path validation
    this.pendingPath = null;

    // Challenge data for validation
    this.pendingChallenges = new Map(); // challengeData -> { path, timestamp, retries }

    // Configuration
    this.maxRetries = options.maxRetries || 3;
    this.probeTimeout = options.probeTimeout || 3000; // ms
    this.maxConcurrentProbes = options.maxConcurrentProbes || 1;

    // Anti-amplification: track bytes received/sent on unvalidated path
    this.unvalidatedBytesSent = 0;
    this.unvalidatedBytesReceived = 0;
    this.amplificationLimit = 3; // RFC 9000 Section 8.1

    // Timers
    this.probeTimers = new Map();
  }

  /**
   * Called when a packet arrives from a different address than expected
   */
  onPacketFromNewAddress(remoteAddress, remotePort, packetSize) {
    // Check if this is actually a new address
    if (this.currentPath.remoteAddress === remoteAddress &&
        this.currentPath.remotePort === remotePort) {
      return false; // Same path
    }

    // NAT rebinding detection: same IP, different port
    const isNATRebinding = this.currentPath.remoteAddress === remoteAddress &&
                           this.currentPath.remotePort !== remotePort;

    // Start path validation
    this.pendingPath = {
      remoteAddress,
      remotePort,
      state: PATH_STATE.VALIDATING,
      isNATRebinding,
    };

    this.unvalidatedBytesReceived = packetSize;
    this.unvalidatedBytesSent = 0;

    this.emit('migrationDetected', {
      oldAddress: this.currentPath.remoteAddress,
      oldPort: this.currentPath.remotePort,
      newAddress: remoteAddress,
      newPort: remotePort,
      isNATRebinding,
    });

    return true;
  }

  /**
   * Generate a PATH_CHALLENGE frame for path validation
   */
  generatePathChallenge() {
    const challengeData = crypto.randomBytes(8);

    this.pendingChallenges.set(challengeData.toString('hex'), {
      path: this.pendingPath,
      timestamp: Date.now(),
      retries: 0,
    });

    // Set probe timeout
    const timerId = setTimeout(() => {
      this._onProbeTimeout(challengeData.toString('hex'));
    }, this.probeTimeout);
    this.probeTimers.set(challengeData.toString('hex'), timerId);

    return {
      type: FRAME_TYPE.PATH_CHALLENGE,
      data: challengeData,
    };
  }

  /**
   * Handle received PATH_CHALLENGE (respond with PATH_RESPONSE)
   */
  handlePathChallenge(data) {
    return {
      type: FRAME_TYPE.PATH_RESPONSE,
      data: Buffer.from(data),
    };
  }

  /**
   * Handle received PATH_RESPONSE
   */
  handlePathResponse(data) {
    const key = data.toString('hex');
    const challenge = this.pendingChallenges.get(key);

    if (!challenge) return false; // Unknown response

    // Clear timeout
    const timerId = this.probeTimers.get(key);
    if (timerId) {
      clearTimeout(timerId);
      this.probeTimers.delete(key);
    }

    this.pendingChallenges.delete(key);

    // Path validated — migrate
    if (this.pendingPath) {
      const oldPath = { ...this.currentPath };
      this.currentPath = {
        remoteAddress: this.pendingPath.remoteAddress,
        remotePort: this.pendingPath.remotePort,
        state: PATH_STATE.VALIDATED,
      };
      this.pendingPath = null;
      this.unvalidatedBytesSent = 0;
      this.unvalidatedBytesReceived = 0;

      this.emit('pathValidated', {
        oldPath,
        newPath: this.currentPath,
      });
    }

    return true;
  }

  /**
   * Check if we can send to unvalidated path (anti-amplification)
   */
  canSendToUnvalidated(bytes) {
    if (!this.pendingPath || this.pendingPath.state !== PATH_STATE.VALIDATING) {
      return true; // Current path is validated
    }
    return (this.unvalidatedBytesSent + bytes) <=
           (this.unvalidatedBytesReceived * this.amplificationLimit);
  }

  /**
   * Track bytes sent to unvalidated path
   */
  onBytesSentToUnvalidated(bytes) {
    this.unvalidatedBytesSent += bytes;
  }

  /**
   * Probe timeout handler
   */
  _onProbeTimeout(challengeKey) {
    const challenge = this.pendingChallenges.get(challengeKey);
    if (!challenge) return;

    challenge.retries++;
    this.probeTimers.delete(challengeKey);

    if (challenge.retries >= this.maxRetries) {
      // Path validation failed
      this.pendingChallenges.delete(challengeKey);

      if (this.pendingPath) {
        this.pendingPath.state = PATH_STATE.FAILED;
        this.emit('pathValidationFailed', {
          path: this.pendingPath,
          reason: 'timeout',
        });
        this.pendingPath = null;
      }
    } else {
      // Retry
      this.emit('retryProbe', challenge);
    }
  }

  /**
   * Initiate active migration to a new path
   */
  initiateMigration(newAddress, newPort) {
    this.pendingPath = {
      remoteAddress: newAddress,
      remotePort: newPort,
      state: PATH_STATE.VALIDATING,
      isNATRebinding: false,
    };

    this.emit('migrationInitiated', {
      from: this.currentPath,
      to: this.pendingPath,
    });

    return this.generatePathChallenge();
  }

  /**
   * Cleanup
   */
  destroy() {
    for (const [, timerId] of this.probeTimers) {
      clearTimeout(timerId);
    }
    this.probeTimers.clear();
    this.pendingChallenges.clear();
    this.removeAllListeners();
  }
}

/**
 * Connection ID Manager - RFC 9000 Section 5.1
 *
 * Manages multiple connection IDs for migration support.
 * Each CID has a sequence number and optional stateless reset token.
 */
class ConnectionIdManager {
  constructor(options = {}) {
    // Our CIDs (that peer uses to address us)
    this.localCids = new Map(); // seqNum -> { cid, resetToken, retired }
    this.nextLocalSeq = 0;
    this.retirePriorTo = 0;

    // Peer's CIDs (that we use to address peer)
    this.peerCids = new Map();   // seqNum -> { cid, resetToken }
    this.activePeerCid = null;
    this.activePeerSeq = 0;

    // Limits
    this.activeConnectionIdLimit = options.activeConnectionIdLimit || 2;
  }

  /**
   * Add a local CID
   */
  addLocalCid(cid, resetToken) {
    const seq = this.nextLocalSeq++;
    this.localCids.set(seq, {
      cid: Buffer.from(cid),
      resetToken: resetToken ? Buffer.from(resetToken) : null,
      retired: false,
    });
    return seq;
  }

  /**
   * Add a peer's CID (from NEW_CONNECTION_ID frame)
   */
  addPeerCid(seqNum, cid, resetToken, retirePriorTo) {
    this.peerCids.set(seqNum, {
      cid: Buffer.from(cid),
      resetToken: resetToken ? Buffer.from(resetToken) : null,
    });

    // Retire old CIDs
    if (retirePriorTo > this.retirePriorTo) {
      this.retirePriorTo = retirePriorTo;
      const toRetire = [];
      for (const [seq] of this.peerCids) {
        if (seq < retirePriorTo) toRetire.push(seq);
      }
      for (const seq of toRetire) {
        this.peerCids.delete(seq);
      }
    }

    // Set active if none set
    if (!this.activePeerCid) {
      this.activePeerCid = Buffer.from(cid);
      this.activePeerSeq = seqNum;
    }

    return { retired: this.retirePriorTo };
  }

  /**
   * Switch to a different peer CID (for migration)
   */
  switchPeerCid() {
    for (const [seq, entry] of this.peerCids) {
      if (seq !== this.activePeerSeq) {
        this.activePeerCid = entry.cid;
        this.activePeerSeq = seq;
        return entry.cid;
      }
    }
    return null; // No alternative CID available
  }

  /**
   * Get NEW_CONNECTION_ID frame to send to peer
   */
  generateNewConnectionIdFrame(cid, resetToken) {
    const seq = this.addLocalCid(cid, resetToken);
    return {
      type: FRAME_TYPE.NEW_CONNECTION_ID,
      sequenceNumber: seq,
      retirePriorTo: Math.max(0, seq - this.activeConnectionIdLimit + 1),
      connectionId: cid,
      statelessResetToken: resetToken || crypto.randomBytes(16),
    };
  }

  /**
   * Build RETIRE_CONNECTION_ID frame
   */
  generateRetireConnectionIdFrame(seqNum) {
    return {
      type: FRAME_TYPE.RETIRE_CONNECTION_ID,
      sequenceNumber: seqNum,
    };
  }
}

module.exports = {
  PathValidator,
  ConnectionIdManager,
  PATH_STATE,
};