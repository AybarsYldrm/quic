'use strict';

// Sequential buffer writer with auto-grow
const { encodeVarInt } = require('../transport/varint.js');

const DEFAULT_SIZE = 4096;
const GROW_FACTOR = 2;

class BufferWriter {
  constructor(initialSize = DEFAULT_SIZE) {
    this.buf = Buffer.alloc(initialSize);
    this.pos = 0;
  }

  get length() {
    return this.pos;
  }

  _ensure(n) {
    if (this.pos + n > this.buf.length) {
      const newSize = Math.max(this.buf.length * GROW_FACTOR, this.pos + n);
      const newBuf = Buffer.alloc(newSize);
      this.buf.copy(newBuf, 0, 0, this.pos);
      this.buf = newBuf;
    }
  }

  writeUInt8(val) {
    this._ensure(1);
    this.buf[this.pos++] = val & 0xff;
    return this;
  }

  writeUInt16(val) {
    this._ensure(2);
    this.buf.writeUInt16BE(val, this.pos);
    this.pos += 2;
    return this;
  }

  writeUInt24(val) {
    this._ensure(3);
    this.buf[this.pos] = (val >> 16) & 0xff;
    this.buf[this.pos + 1] = (val >> 8) & 0xff;
    this.buf[this.pos + 2] = val & 0xff;
    this.pos += 3;
    return this;
  }

  writeUInt32(val) {
    this._ensure(4);
    this.buf.writeUInt32BE(val, this.pos);
    this.pos += 4;
    return this;
  }

  writeBytes(data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    this._ensure(buf.length);
    buf.copy(this.buf, this.pos);
    this.pos += buf.length;
    return this;
  }

  writeLenPrefixed8(data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    this.writeUInt8(buf.length);
    this.writeBytes(buf);
    return this;
  }

  writeLenPrefixed16(data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    this.writeUInt16(buf.length);
    this.writeBytes(buf);
    return this;
  }

  writeLenPrefixed24(data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    this.writeUInt24(buf.length);
    this.writeBytes(buf);
    return this;
  }

  writeVarInt(value) {
    const encoded = encodeVarInt(value);
    this.writeBytes(encoded);
    return this;
  }

  // Pozisyonu kaydet (sonra geri dönüp length yazmak için)
  mark() {
    return this.pos;
  }

  // Belirli bir pozisyona UInt24 yaz (length backfill)
  writeUInt24At(pos, val) {
    this.buf[pos] = (val >> 16) & 0xff;
    this.buf[pos + 1] = (val >> 8) & 0xff;
    this.buf[pos + 2] = val & 0xff;
    return this;
  }

  writeUInt16At(pos, val) {
    this.buf.writeUInt16BE(val, pos);
    return this;
  }

  toBuffer() {
    return Buffer.from(this.buf.subarray(0, this.pos));
  }

  reset() {
    this.pos = 0;
    return this;
  }
}

module.exports = {
  BufferWriter
};