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

    // Send state
    this.sendState = STREAM_STATE.READY;
    this.sendBuffer = Buffer.alloc(0);
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

  write(data, fin = false) {
    if (this.destroyed) return this;
    if (this._finSent) return this;
    if (this.sendState === STREAM_STATE.RESET_SENT) return this;

    if (typeof data === 'string') data = Buffer.from(data, 'utf8');

    this.sendBuffer = Buffer.concat([this.sendBuffer, data]);
    if (fin) {
      this.sendFin = true;
      this.sendFinOffset = this.sendOffset + this.sendBuffer.length;
    }

    if (this.sendState === STREAM_STATE.READY) {
      this.sendState = STREAM_STATE.SEND;
    }

    // Trigger flush on next tick to batch writes
    if (this.connection && typeof this.connection._flushAll === 'function') {
      if (!this._flushScheduled) {
        this._flushScheduled = true;
        queueMicrotask(() => {
          this._flushScheduled = false;
          this.connection._flushAll();
        });
      }
    }

    return this;
  }

  end(data) {
    if (data) {
      return this.write(data, true);
    }
    this.sendFin = true;
    this.sendFinOffset = this.sendOffset + this.sendBuffer.length;
    if (this.sendState === STREAM_STATE.READY) {
      this.sendState = STREAM_STATE.SEND;
    }

    if (this.connection && typeof this.connection._flushAll === 'function') {
      if (!this._flushScheduled) {
        this._flushScheduled = true;
        queueMicrotask(() => {
          this._flushScheduled = false;
          this.connection._flushAll();
        });
      }
    }

    return this;
  }

  resetStream(errorCode = 0) {
    this.sendState = STREAM_STATE.RESET_SENT;
    this.connection._sendResetStream(this.id, errorCode, this.sendOffset);
  }

  _getPendingData(maxBytes) {
    // Guards: don't extract data from finished/destroyed streams
    if (this.destroyed) return null;
    if (this._finSent) return null;
    if (this.sendState === STREAM_STATE.DATA_SENT ||
        this.sendState === STREAM_STATE.DATA_RECVD ||
        this.sendState === STREAM_STATE.RESET_SENT) {
      return null;
    }

    if (this.sendBuffer.length === 0 && !this.sendFin) return null;

    const available = Math.min(
      this.sendBuffer.length,
      maxBytes,
      this.maxSendData - this.sentData
    );

    if (available <= 0 && !this.sendFin) return null;

    const data = this.sendBuffer.subarray(0, available);
    const offset = this.sendOffset;
    const fin = this.sendFin && available === this.sendBuffer.length;

    this.sendBuffer = this.sendBuffer.subarray(available);
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

  _hasPendingData() {
    if (this.destroyed || this._finSent) return false;
    if (this.sendState === STREAM_STATE.DATA_SENT ||
        this.sendState === STREAM_STATE.DATA_RECVD) return false;
    return this.sendBuffer.length > 0 || this.sendFin;
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
    this.sendBuffer = Buffer.alloc(0);
    this.recvBuffer.clear();
    this.removeAllListeners();
  }
}

function streamType(streamId) { return streamId & 0x03; }
function isClientInitiated(streamId) { return (streamId & 0x01) === 0; }
function isBidirectional(streamId) { return (streamId & 0x02) === 0; }

module.exports = { QuicStream, STREAM_STATE, streamType, isClientInitiated, isBidirectional };