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
  // HTTP/2 spesifik ek durumlar (opsiyonel takip için)
  HALF_CLOSED_L:  'half-closed-local',
  HALF_CLOSED_R:  'half-closed-remote',
  CLOSED:         'closed'
};

class UnifiedStream extends EventEmitter {
  constructor(streamId, connection, options = {}) {
    super();
    this.id = streamId;
    this.connection = connection;
    
    // Ağ tipi: 'quic' veya 'http2'
    this.transport = options.transport || 'quic';

    // Başlatıcı ve yön tayini
    if (this.transport === 'http2') {
      this.initiator = (streamId % 2 === 1) ? 'client' : 'server';
      this.bidirectional = true; // H2 akışları genelde çift yönlüdür
    } else {
      this.initiator = (streamId & 0x01) === 0 ? 'client' : 'server';
      this.bidirectional = (streamId & 0x02) === 0;
    }

    // Gönderim Durumu
    this.sendState = STREAM_STATE.READY;
    this._sendQueue = [];
    this._sendQueueBytes = 0;
    this.sendOffset = 0; // QUIC için toplam gönderilen byte
    this.sentOffset = 0; // QUIC ACK takibi
    this.sendFin = false;
    this.sendFinOffset = -1;
    this._finSent = false;

    // Alım Durumu
    this.recvState = STREAM_STATE.RECV;
    this.recvBuffer = new Map();
    this.recvOffset = 0;
    this.recvFin = false;
    this.recvFinOffset = -1;
    this.readableData = Buffer.alloc(0);

    // ==========================================
    // FLOW CONTROL (Akış Kontrolü)
    // ==========================================
    
    // QUIC (Mutlak Ofset) Flow Control
    this.maxSendData = options.maxStreamData || 262144;
    this.maxRecvData = options.initialMaxStreamData || 262144;
    this.sentData = 0;
    this.recvData = 0;

    // HTTP/2 (Kayan Pencere / Sliding Window) Flow Control
    this.sendWindow = options.sendWindow !== undefined ? options.sendWindow : 65535;
    this.recvWindow = options.recvWindow !== undefined ? options.recvWindow : 65535;

    this.unackedRanges = [];
    this._pendingEnd = false;
    this.destroyed = false;
    this.headersSent = false;

    this.on('newListener', (event) => {
      if (event === 'data') {
        queueMicrotask(() => this._emitReadable());
      }
    });
  }

  // Geriye dönük uyumluluk (connection.js için)
  get sendBuffer() {
    return { length: this._sendQueueBytes };
  }

  // ==========================================
  // HTTP/2 HEADER YÖNETİMİ
  // ==========================================

  sendHeaders(headers, options = {}) {
    if (this.destroyed) return;
    this.headersSent = true;
    if (typeof this.connection._sendHeaders === 'function') {
      this.connection._sendHeaders(this.id, headers, options);
    }
    if (options.endStream) {
      this.end();
    }
  }

  // ==========================================
  // VERİ GÖNDERİMİ (WRITE)
  // ==========================================

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
    if (!this.connection) return;
    
    // Ağ katmanındaki ana flush fonksiyonunu tetikle
    const flushFn = this.connection._flushAll || this.connection._flushStreams;
    if (typeof flushFn !== 'function') return;

    if (this._flushScheduled) return;
    this._flushScheduled = true;
    
    queueMicrotask(() => {
      this._flushScheduled = false;
      flushFn.call(this.connection);
    });
  }

  // HTTP/2 Modunda Window Update Geldiğinde Çağrılır
  updateSendWindow(delta) {
    this.sendWindow += delta;
    if (this.sendWindow > 0 && this._sendQueueBytes > 0) {
      this._scheduleFlush();
    }
  }

  // ==========================================
  // PULL (Veri Çekme) - Connection katmanı çağırır
  // ==========================================

  _getPendingData(maxBytes) {
    if (this.destroyed) return null;
    if (this._finSent) return null;
    if (this.sendState === STREAM_STATE.DATA_SENT ||
        this.sendState === STREAM_STATE.DATA_RECVD ||
        this.sendState === STREAM_STATE.RESET_SENT) {
      return null;
    }

    if (this._sendQueueBytes === 0 && !this.sendFin) return null;

    // Protokole göre Akış Kontrolü Limiti hesapla
    const flowLimit = this.transport === 'http2' 
      ? this.sendWindow 
      : (this.maxSendData - this.sentData);

    const available = Math.min(
      this._sendQueueBytes,
      maxBytes,
      flowLimit
    );

    // Pencere kapalıysa ve FIN göndermeyeceksek bekle
    if (available <= 0 && !this.sendFin) return null;

    let data;
    if (available === 0) {
      // Sadece FIN bayrağı taşınacak boş frame
      data = Buffer.alloc(0);
    } else if (this._sendQueue.length === 1 && this._sendQueue[0].length === available) {
      // Hot Path: Kopyalama yok (Zero-Copy)
      data = this._sendQueue[0];
      this._sendQueue.length = 0;
    } else {
      data = this._consumeFromQueue(available);
    }

    this._sendQueueBytes -= available;
    const offset = this.sendOffset;
    const fin = this.sendFin && this._sendQueueBytes === 0;

    this.sendOffset += available;
    
    // Protokol bazlı state güncellemesi
    if (this.transport === 'http2') {
      this.sendWindow -= available;
    } else {
      this.sentData += available;
      if (available > 0) {
        this.unackedRanges.push({ offset, length: available });
      }
    }

    if (fin) {
      this.sendState = STREAM_STATE.DATA_SENT;
    }

    return { streamId: this.id, offset, data, fin };
  }

  _consumeFromQueue(n) {
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

  // ==========================================
  // VERİ ALIMI (RECV) - Hem Sıralı Hem Sırasız
  // ==========================================

  // HTTP/2 sıralı çalışır, offset'i kendimiz yönetiriz. QUIC ofset verir.
  receiveData(data, fin = false, offset = null) {
    const actualOffset = offset !== null ? offset : this.recvOffset;
    this._receiveData(actualOffset, data, fin);
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
      // H2 modunda veri doğrudan sona eklenir, QUIC modunda Map'e atılıp birleştirilir
      this.recvBuffer.set(offset, Buffer.isBuffer(data) ? data : Buffer.from(data));
      this.recvData += data.length;
      
      // H2 Flow Control penceresi güncellenmeli (Opsiyonel: auto-ack)
      if (this.transport === 'http2' && typeof this.connection._sendWindowUpdate === 'function') {
        this.recvWindow -= data.length;
        if (this.recvWindow < 32768) {
          const increment = 65535 - this.recvWindow;
          this.connection._sendWindowUpdate(this.id, increment);
          this.recvWindow += increment;
        }
      }
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

  // Sadece QUIC için: Gönderilen verinin onaylanması
  _ackData(offset, length) {
    if (this.transport === 'http2') return;

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

  // ==========================================
  // HATA VE SIFIRLAMA (RESET)
  // ==========================================

  resetStream(errorCode = 0) {
    if (this.destroyed) return;
    this.sendState = STREAM_STATE.RESET_SENT;
    
    if (this.transport === 'http2') {
      if (typeof this.connection._sendRstStream === 'function') {
        this.connection._sendRstStream(this.id, errorCode);
      }
    } else {
      if (typeof this.connection._sendResetStream === 'function') {
        this.connection._sendResetStream(this.id, errorCode, this.sendOffset);
      }
    }
    this.destroy();
  }

  rstStream(errorCode = 0) {
    // HTTP/2 alias'ı
    this.resetStream(errorCode);
  }

  _handleStopSending(errorCode) {
    this.resetStream(errorCode);
    this.emit('stopSending', errorCode);
    this.destroy();
  }

  _handleResetStream(errorCode, finalSize) {
    this.recvState = STREAM_STATE.RESET_RECVD;
    if (finalSize !== undefined) this.recvFinOffset = finalSize;
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

// Global protocol helpers
function streamType(streamId) { return streamId & 0x03; }
function isClientInitiated(streamId) { return (streamId & 0x01) === 0; }
function isBidirectional(streamId) { return (streamId & 0x02) === 0; }

// Modül dışarıya hem HTTP/2 hem QUIC tarafında kullanılabilmesi için aliaslar ile sunuluyor.
module.exports = { 
  UnifiedStream, 
  QuicStream: UnifiedStream,   // QUIC engine için alias
  Http2Stream: UnifiedStream,  // HTTP/2 engine için alias
  STREAM_STATE, 
  streamType, 
  isClientInitiated, 
  isBidirectional 
};