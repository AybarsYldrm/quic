'use strict';

/**
 * QUIC Variable-Length Integer Encoding - RFC 9000 Section 16
 *
 * Uses 1, 2, 4, or 8 bytes depending on value:
 * - 6-bit:  0-63                  (prefix 00)
 * - 14-bit: 0-16383               (prefix 01)
 * - 30-bit: 0-1073741823          (prefix 10)
 * - 62-bit: 0-4611686018427387903 (prefix 11)
 */

function decodeVarInt(buf, offset) {
  if (offset >= buf.length) {
    throw new RangeError('VarInt: buffer underflow');
  }

  const first = buf[offset];
  const prefix = first >> 6;
  let value, length;

  switch (prefix) {
    case 0: // 6-bit
      value = first & 0x3f;
      length = 1;
      break;

    case 1: // 14-bit
      if (offset + 2 > buf.length) throw new RangeError('VarInt: need 2 bytes');
      value = ((first & 0x3f) << 8) | buf[offset + 1];
      length = 2;
      break;

    case 2: // 30-bit
      if (offset + 4 > buf.length) throw new RangeError('VarInt: need 4 bytes');
      value = ((first & 0x3f) << 24) |
              (buf[offset + 1] << 16) |
              (buf[offset + 2] << 8) |
              buf[offset + 3];
      length = 4;
      break;

    case 3: { // 62-bit
      if (offset + 8 > buf.length) throw new RangeError('VarInt: need 8 bytes');
      const hi = ((first & 0x3f) << 24) |
                 (buf[offset + 1] << 16) |
                 (buf[offset + 2] << 8) |
                 buf[offset + 3];
      const lo = (buf[offset + 4] << 24) |
                 (buf[offset + 5] << 16) |
                 (buf[offset + 6] << 8) |
                 buf[offset + 7];
      // Use BigInt for 62-bit values to avoid precision loss
      value = (BigInt(hi >>> 0) << 32n) | BigInt(lo >>> 0);
      if (value <= BigInt(Number.MAX_SAFE_INTEGER)) {
        value = Number(value);
      }
      length = 8;
      break;
    }
  }

  return { value, length };
}

function encodeVarInt(value) {
  if (typeof value === 'bigint') {
    return encodeVarIntBigInt(value);
  }

  if (value < 0) throw new RangeError('VarInt: negative value');

  if (value <= 0x3f) {
    const buf = Buffer.allocUnsafe(1);
    buf[0] = value;
    return buf;
  }

  if (value <= 0x3fff) {
    const buf = Buffer.allocUnsafe(2);
    buf[0] = 0x40 | (value >> 8);
    buf[1] = value & 0xff;
    return buf;
  }

  if (value <= 0x3fffffff) {
    const buf = Buffer.allocUnsafe(4);
    buf[0] = 0x80 | (value >> 24);
    buf[1] = (value >> 16) & 0xff;
    buf[2] = (value >> 8) & 0xff;
    buf[3] = value & 0xff;
    return buf;
  }

  // 62-bit
  return encodeVarIntBigInt(BigInt(value));
}

function encodeVarIntBigInt(value) {
  if (value < 0n) throw new RangeError('VarInt: negative value');
  if (value > 0x3fffffffffffffffn) throw new RangeError('VarInt: exceeds 62-bit max');

  const buf = Buffer.allocUnsafe(8);
  const hi = Number((value >> 32n) & 0xffffffffn);
  const lo = Number(value & 0xffffffffn);

  buf[0] = 0xc0 | ((hi >> 24) & 0x3f);
  buf[1] = (hi >> 16) & 0xff;
  buf[2] = (hi >> 8) & 0xff;
  buf[3] = hi & 0xff;
  buf[4] = (lo >> 24) & 0xff;
  buf[5] = (lo >> 16) & 0xff;
  buf[6] = (lo >> 8) & 0xff;
  buf[7] = lo & 0xff;

  return buf;
}

function varIntLength(value) {
  if (typeof value === 'bigint') {
    if (value <= 0x3fn) return 1;
    if (value <= 0x3fffn) return 2;
    if (value <= 0x3fffffffn) return 4;
    return 8;
  }
  if (value <= 0x3f) return 1;
  if (value <= 0x3fff) return 2;
  if (value <= 0x3fffffff) return 4;
  return 8;
}

/**
 * Write a varint into buf at offset. Returns new offset.
 */
function writeVarInt(buf, offset, value) {
  const encoded = encodeVarInt(value);
  encoded.copy(buf, offset);
  return offset + encoded.length;
}

module.exports = { decodeVarInt, encodeVarInt, varIntLength, writeVarInt };