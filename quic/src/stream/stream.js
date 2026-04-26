'use strict';

const { EventEmitter } = require('events');

const STREAM_STATE = {
  READY:          'ready',
  SEND:           'send',
  DATA_SENT:      'data-sent',
  DATA_RECVD:     'data-recvd',
  RESET_SENT:     'reset-sent',
  RESET_RECVD:    'reset-recvd',
  RECV:           'recv',
  SIZE_KNOWN:     'size-known',
  ALL_DATA_RECVD: 'all-data-recvd',
  READ:           'read',
  RESET_READ:     'reset-read',
};

class QuicStream extends EventEmitter {
  constructor(streamId, connection, options = {}) {
    super();
    this.id = streamId;
    this.connection = connection;

    this.initiator = (streamId & 0x01) === 0 ? 'client' : 'server';
    this.bidirectional = (streamId & 0x02) === 0;

    // Send state. We keep an array of chunks instead of a single
    // Buffer so write()'s common case is a cheap push instead of a
    // Buffer.concat (which would be O(n) per write — O(n²) for many
    // small writes). `sendBuffer.length` is exposed as a getter for
    // backwards compatibility with connection.js's old interface.
    this.sendState = STREAM_STATE.READY;
    this._sendQueue = [];
    this._sendQueueBytes = 0;
    this.sendOffset = 0;
    this.sentOffset = 0;
    this.sendFin = false;
    this.sendFinOffset = -1;
    this._finSent = false;

    // Receive state
    this.recvState = STREAM_STATE.RECV;
    this.recvBuffer = new Map();
    this.recvOffset = 0;
    this.recvFin = false;
    this.recvFinOffset = -1;
    this.readableData = Buffer.alloc(0);

    // Flow control
    this.maxSendData = options.maxStreamData || 262144;
    this.maxRecvData = options.initialMaxStreamData || 262144;
    this.sentData = 0;
    this.recvData = 0;

    this.unackedRanges = [];
    this._pendingEnd = false;
    this.destroyed = false;

    this.on('newListener', (event) => {
      if (event === 'data') {
        queueMicrotask(() => this._emitReadable());
      }
    });
  }

  // Backwards-compat: external callers (connection.js) read this as
  // `stream.sendBuffer.length`. Returning a synthetic { length } object
  // avoids touching every call site.
  get sendBuffer() {
    return { length: this._sendQueueBytes };
  }

  write(data, fin = false) {
    if (this.destroyed) return this;
    if (this._finSent) return this;
    if (this.sendState === STREAM_STATE.RESET_SENT) return this;

    if (typeof data === 'string') data = Buffer.from(data, 'utf8');

    if (data.length > 0) {
      this._sendQueue.push(data);
      this._sendQueueBytes += data.length;
    }
    if (fin) {
      this.sendFin = true;
      this.sendFinOffset = this.sendOffset + this._sendQueueBytes;
    }

    if (this.sendState === STREAM_STATE.READY) {
      this.sendState = STREAM_STATE.SEND;
    }

    this._scheduleFlush();
    return this;
  }

  end(data) {
    if (data) {
      return this.write(data, true);
    }
    this.sendFin = true;
    this.sendFinOffset = this.sendOffset + this._sendQueueBytes;
    if (this.sendState === STREAM_STATE.READY) {
      this.sendState = STREAM_STATE.SEND;
    }
    this._scheduleFlush();
    return this;
  }

  _scheduleFlush() {
    if (!this.connection || typeof this.connection._flushAll !== 'function') return;
    if (this._flushScheduled) return;
    this._flushScheduled = true;
    queueMicrotask(() => {
      this._flushScheduled = false;
      this.connection._flushAll();
    });
  }

  resetStream(errorCode = 0) {
    this.sendState = STREAM_STATE.RESET_SENT;
    this.connection._sendResetStream(this.id, errorCode, this.sendOffset);
  }

  _getPendingData(maxBytes) {
    if (this.destroyed) return null;
    if (this._finSent) return null;
    if (this.sendState === STREAM_STATE.DATA_SENT ||
        this.sendState === STREAM_STATE.DATA_RECVD ||
        this.sendState === STREAM_STATE.RESET_SENT) {
      return null;
    }

    if (this._sendQueueBytes === 0 && !this.sendFin) return null;

    const available = Math.min(
      this._sendQueueBytes,
      maxBytes,
      this.maxSendData - this.sentData
    );

    if (available <= 0 && !this.sendFin) return null;

    let data;
    if (available === 0) {
      // FIN-only frame
      data = Buffer.alloc(0);
    } else if (this._sendQueue.length === 1 && this._sendQueue[0].length === available) {
      // Hot path: one-chunk write that fits entirely → zero copies.
      data = this._sendQueue[0];
      this._sendQueue.length = 0;
    } else {
      data = this._consumeFromQueue(available);
    }

    this._sendQueueBytes -= available;
    const offset = this.sendOffset;
    const fin = this.sendFin && this._sendQueueBytes === 0;

    this.sendOffset += available;
    this.sentData += available;

    if (available > 0) {
      this.unackedRanges.push({ offset, length: available });
    }

    if (fin) {
      this.sendState = STREAM_STATE.DATA_SENT;
    }

    return { streamId: this.id, offset, data, fin };
  }

  _consumeFromQueue(n) {
    // Pull exactly `n` bytes off the head of _sendQueue, preserving
    // any remainder of the boundary chunk in place.
    const out = [];
    let remaining = n;
    while (remaining > 0) {
      const head = this._sendQueue[0];
      if (head.length <= remaining) {
        out.push(head);
        remaining -= head.length;
        this._sendQueue.shift();
      } else {
        out.push(head.subarray(0, remaining));
        this._sendQueue[0] = head.subarray(remaining);
        remaining = 0;
      }
    }
    return out.length === 1 ? out[0] : Buffer.concat(out, n);
  }

  _hasPendingData() {
    if (this.destroyed || this._finSent) return false;
    if (this.sendState === STREAM_STATE.DATA_SENT ||
        this.sendState === STREAM_STATE.DATA_RECVD) return false;
    return this._sendQueueBytes > 0 || this.sendFin;
  }

  _receiveData(offset, data, fin) {
    if (this.recvState === STREAM_STATE.ALL_DATA_RECVD ||
        this.recvState === STREAM_STATE.READ) {
      return;
    }

    if (fin) {
      this.recvFin = true;
      this.recvFinOffset = offset + data.length;
      this.recvState = STREAM_STATE.SIZE_KNOWN;
    }

    if (data.length > 0) {
      this.recvBuffer.set(offset, Buffer.from(data));
      this.recvData += data.length;
    }

    this._reassemble();
  }

  _reassemble() {
    let assembled = false;

    while (this.recvBuffer.has(this.recvOffset)) {
      const chunk = this.recvBuffer.get(this.recvOffset);
      this.recvBuffer.delete(this.recvOffset);
      this.readableData = Buffer.concat([this.readableData, chunk]);
      this.recvOffset += chunk.length;
      assembled = true;
    }

    if (assembled) {
      this._emitReadable();
    }

    if (this.recvFin && this.recvOffset >= this.recvFinOffset) {
      this.recvState = STREAM_STATE.ALL_DATA_RECVD;
      if (this._pendingEnd) return;
      if (this.readableData.length > 0) {
        this._pendingEnd = true;
      } else {
        this.emit('end');
      }
    }
  }

  _emitReadable() {
    if (this.listenerCount('data') > 0 && this.readableData.length > 0) {
      const data = this.readableData;
      this.readableData = Buffer.alloc(0);
      this.emit('data', data);
      if (this._pendingEnd && this.readableData.length === 0) {
        this._pendingEnd = false;
        this.emit('end');
      }
    }
  }

  _ackData(offset, length) {
    this.unackedRanges = this.unackedRanges.filter(r => {
      if (r.offset >= offset && r.offset + r.length <= offset + length) {
        return false;
      }
      return true;
    });

    this.sentOffset = Math.max(this.sentOffset, offset + length);

    if (this.sendState === STREAM_STATE.DATA_SENT &&
        this.unackedRanges.length === 0) {
      this.sendState = STREAM_STATE.DATA_RECVD;
      this.emit('finish');
    }
  }

  _handleStopSending(errorCode) {
    this.resetStream(errorCode);
    this.emit('stopSending', errorCode);
    this.destroy();
  }

  _handleResetStream(errorCode, finalSize) {
    this.recvState = STREAM_STATE.RESET_RECVD;
    this.recvFinOffset = finalSize;
    this.emit('reset', errorCode);
    this.destroy();
  }

  destroy() {
    if (this.destroyed) return;
    this.destroyed = true;
    this._sendQueue.length = 0;
    this._sendQueueBytes = 0;
    this.recvBuffer.clear();
    this.readableData = Buffer.alloc(0);
    this.removeAllListeners();
  }
}

function streamType(streamId) { return streamId & 0x03; }
function isClientInitiated(streamId) { return (streamId & 0x01) === 0; }
function isBidirectional(streamId) { return (streamId & 0x02) === 0; }

module.exports = { QuicStream, STREAM_STATE, streamType, isClientInitiated, isBidirectional };