'use strict';

// Sequential buffer reader with offset tracking
class BufferReader {
  constructor(buffer, offset = 0) {
    this.buf = buffer;
    this.pos = offset;
  }

  get remaining() {
    return this.buf.length - this.pos;
  }

  get eof() {
    return this.pos >= this.buf.length;
  }

  ensure(n) {
    if (this.remaining < n) {
      throw new RangeError(`BufferReader: need ${n} bytes, have ${this.remaining}`);
    }
  }

  readUInt8() {
    this.ensure(1);
    return this.buf[this.pos++];
  }

  readUInt16() {
    this.ensure(2);
    const val = this.buf.readUInt16BE(this.pos);
    this.pos += 2;
    return val;
  }

  readUInt24() {
    this.ensure(3);
    const val = (this.buf[this.pos] << 16) | (this.buf[this.pos + 1] << 8) | this.buf[this.pos + 2];
    this.pos += 3;
    return val;
  }

  readUInt32() {
    this.ensure(4);
    const val = this.buf.readUInt32BE(this.pos);
    this.pos += 4;
    return val;
  }

  readBytes(n) {
    this.ensure(n);
    const slice = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return slice;
  }

  readLenPrefixed8() {
    const len = this.readUInt8();
    return this.readBytes(len);
  }

  readLenPrefixed16() {
    const len = this.readUInt16();
    return this.readBytes(len);
  }

  readLenPrefixed24() {
    const len = this.readUInt24();
    return this.readBytes(len);
  }

  peek(n = 1) {
    this.ensure(n);
    return this.buf.subarray(this.pos, this.pos + n);
  }

  skip(n) {
    this.ensure(n);
    this.pos += n;
  }

  // QUIC VarInt desteği
  readVarInt() {
    const { decodeVarInt } = getVarIntDecoder();
    const { value, length } = decodeVarInt(this.buf, this.pos);
    this.pos += length;
    return value;
  }
}

// Lazy initialization to avoid circular deps and keep logic contained
let _varint;
function getVarIntDecoder() {
  if (!_varint) {
    _varint = {
      decodeVarInt(buf, offset) {
        const first = buf[offset];
        const prefix = first >> 6;
        switch (prefix) {
          case 0: return { value: first & 0x3f, length: 1 };
          case 1: return { value: ((first & 0x3f) << 8) | buf[offset + 1], length: 2 };
          case 2: return {
            value: ((first & 0x3f) << 24) | (buf[offset + 1] << 16) |
                   (buf[offset + 2] << 8) | buf[offset + 3],
            length: 4
          };
          case 3: {
            const hi = ((first & 0x3f) << 24) | (buf[offset + 1] << 16) |
                       (buf[offset + 2] << 8) | buf[offset + 3];
            const lo = (buf[offset + 4] << 24) | (buf[offset + 5] << 16) |
                       (buf[offset + 6] << 8) | buf[offset + 7];
            return { value: Number((BigInt(hi) << 32n) | BigInt(lo >>> 0)), length: 8 };
          }
        }
      }
    };
  }
  return _varint;
}

module.exports = {
  BufferReader
};