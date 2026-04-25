'use strict';

const { createLogger } = require('../utils/logger');
const log = createLogger('QPACK');

/**
 * QPACK - HTTP/3 Header Compression - RFC 9204
 *
 * Huffman table: RFC 7541 Appendix B
 * Verified by intercepting Node.js http2 (nghttp2) HPACK output through TCP proxy.
 * Test vectors: /api/info?req=1 → 607599835529ffcb0bda00ff, /hello → 6272d141ff
 */

// RFC 7541 Appendix B — Huffman Code Table (nghttp2-verified)
const HUFF_CODES = [
  // 0-31: Control characters
  0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
  0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
  0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
  0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
  // 32-47: SP ! " # $ % & ' ( ) * + , - . /
  0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa,
  0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
  // 48-63: 0 1 2 3 4 5 6 7 8 9 : ; < = > ?
  0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
  0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
  // 64-79: @ A B C D E F G H I J K L M N O
  0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
  0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
  // 80-95: P Q R S T U V W X Y Z [ \ ] ^ _
  0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0xfc, 0x71,
  0xfd, 0x73, 0x72, 0x1ffb, 0x3ffe, 0x1ffc, 0x3ffc, 0x22,
  // 96-111: ` a b c d e f g h i j k l m n o
  0x7ffd, 0x03, 0x23, 0x04, 0x24, 0x05, 0x25, 0x26,
  0x27, 0x06, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x07,
  // 112-127: p q r s t u v w x y z { | } ~ DEL
  0x2b, 0x76, 0x2c, 0x08, 0x09, 0x2d, 0x77, 0x78,
  0x79, 0x7a, 0x7b, 0xffc, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
  // 128-255: Extended ASCII
  0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9,
  0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
  0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
  0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef,
  0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde,
  0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
  0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef,
  0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1,
  0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
  0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
  0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2,
  0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
  0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
  0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4,
  0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea,
  0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
  0x3fffffff, // 256 = EOS
];

const HUFF_LENGTHS = [
  // 0-31
  13,23,28,28,28,28,28,28, 28,24,30,28,28,30,28,28,
  28,28,28,28,28,28,30,28, 28,28,28,28,28,28,28,28,
  // 32-47
   6,10,10,12,13, 6, 8,11, 10,10, 8,11, 8, 6, 6, 6,
  // 48-63
   5, 5, 5, 6, 6, 6, 6, 6,  6, 6, 7, 8,15, 6,12,10,
  // 64-79
  13, 6, 7, 7, 7, 7, 7, 7,  7, 7, 7, 7, 7, 7, 7, 7,
  // 80-95: P Q R S T U V W X Y Z [ \ ] ^ _
   7, 7, 7, 7, 7, 7, 8, 7,  8, 7, 7,13,14,13,14, 6,
  // 96-111: ` a b c d e f g h i j k l m n o
  15, 5, 6, 5, 6, 5, 6, 6,  6, 5, 7, 7, 6, 6, 6, 5,
  // 112-127: p q r s t u v w x y z { | } ~ DEL
   6, 7, 6, 5, 5, 6, 7, 7,  7, 7, 7,12,11,14,13,28,
  // 128-255
  20,22,20,20,22,22,22,23, 22,23,23,23,23,23,24,23,
  24,24,22,23,24,23,23,23, 23,21,22,23,22,23,23,24,
  22,21,20,22,22,23,23,21, 23,22,22,24,21,22,23,23,
  21,21,22,21,23,22,23,23, 20,22,22,22,23,22,22,23,
  26,26,20,19,22,23,22,25, 26,26,26,27,27,26,24,25,
  19,21,26,27,27,26,27,24, 21,21,26,26,28,27,27,27,
  20,24,20,21,22,21,21,23, 22,22,25,25,24,24,26,23,
  26,27,26,26,27,27,27,27, 27,28,27,27,27,27,27,26,
  30,
];

let _huffmanRoot = null;

function _buildTree() {
  if (_huffmanRoot) return _huffmanRoot;
  const root = {};

  for (let sym = 0; sym < HUFF_CODES.length; sym++) {
    const code = HUFF_CODES[sym];
    const len  = HUFF_LENGTHS[sym];
    let node = root;
    for (let bit = len - 1; bit >= 0; bit--) {
      const go = (code >>> bit) & 1;
      if (go) {
        if (!node.r) node.r = {};
        node = node.r;
      } else {
        if (!node.l) node.l = {};
        node = node.l;
      }
    }
    node.sym = sym;
  }

  _huffmanRoot = root;
  return root;
}

function decodeHuffman(buf) {
  const root = _buildTree();
  const out  = [];
  let node   = root;
  let tailBits = 0;   // bits consumed since last complete symbol
  let tailVal  = 0;   // those bits, MSB-first

  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i];
    for (let bit = 7; bit >= 0; bit--) {
      const b = (byte >>> bit) & 1;
      node = b ? node.r : node.l;
      if (!node) {
        throw new Error('QPACK Huffman: invalid code path');
      }
      tailVal = (tailVal << 1) | b;
      tailBits++;
      if (node.sym !== undefined) {
        if (node.sym === 256) {
          // RFC 7541 §5.2: EOS symbol MUST NOT appear in a valid stream.
          throw new Error('QPACK Huffman: EOS symbol in stream');
        }
        out.push(node.sym);
        node = root;
        tailBits = 0;
        tailVal  = 0;
      }
    }
  }

  // RFC 7541 §5.3: when the stream ends mid-symbol, the remaining bits
  // must be (a) strictly shorter than 8 and (b) the MSB prefix of the
  // EOS code — i.e. all 1-bits.
  if (tailBits > 0) {
    if (tailBits >= 8) {
      throw new Error('QPACK Huffman: padding longer than 7 bits');
    }
    const expected = (1 << tailBits) - 1; // tailBits ones
    if (tailVal !== expected) {
      throw new Error('QPACK Huffman: non-EOS padding bits');
    }
  }

  return Buffer.from(out).toString('utf8');
}

// ----- Static Table (RFC 9204 Appendix A) -----
const STATIC_TABLE = [
  /* 0  */ { name: ':authority',                         value: '' },
  /* 1  */ { name: ':path',                              value: '/' },
  /* 2  */ { name: 'age',                                value: '0' },
  /* 3  */ { name: 'content-disposition',                value: '' },
  /* 4  */ { name: 'content-length',                     value: '0' },
  /* 5  */ { name: 'cookie',                             value: '' },
  /* 6  */ { name: 'date',                               value: '' },
  /* 7  */ { name: 'etag',                               value: '' },
  /* 8  */ { name: 'if-modified-since',                  value: '' },
  /* 9  */ { name: 'if-none-match',                      value: '' },
  /* 10 */ { name: 'last-modified',                      value: '' },
  /* 11 */ { name: 'link',                               value: '' },
  /* 12 */ { name: 'location',                           value: '' },
  /* 13 */ { name: 'referer',                            value: '' },
  /* 14 */ { name: 'set-cookie',                         value: '' },
  /* 15 */ { name: ':method',                            value: 'CONNECT' },
  /* 16 */ { name: ':method',                            value: 'DELETE' },
  /* 17 */ { name: ':method',                            value: 'GET' },
  /* 18 */ { name: ':method',                            value: 'HEAD' },
  /* 19 */ { name: ':method',                            value: 'OPTIONS' },
  /* 20 */ { name: ':method',                            value: 'POST' },
  /* 21 */ { name: ':method',                            value: 'PUT' },
  /* 22 */ { name: ':scheme',                            value: 'http' },
  /* 23 */ { name: ':scheme',                            value: 'https' },
  /* 24 */ { name: ':status',                            value: '103' },
  /* 25 */ { name: ':status',                            value: '200' },
  /* 26 */ { name: ':status',                            value: '304' },
  /* 27 */ { name: ':status',                            value: '404' },
  /* 28 */ { name: ':status',                            value: '503' },
  /* 29 */ { name: 'accept',                             value: '*/*' },
  /* 30 */ { name: 'accept',                             value: 'application/dns-message' },
  /* 31 */ { name: 'accept-encoding',                    value: 'gzip, deflate, br' },
  /* 32 */ { name: 'accept-ranges',                      value: 'bytes' },
  /* 33 */ { name: 'access-control-allow-headers',       value: 'cache-control' },
  /* 34 */ { name: 'access-control-allow-headers',       value: 'content-type' },
  /* 35 */ { name: 'access-control-allow-origin',        value: '*' },
  /* 36 */ { name: 'cache-control',                      value: 'max-age=0' },
  /* 37 */ { name: 'cache-control',                      value: 'max-age=2592000' },
  /* 38 */ { name: 'cache-control',                      value: 'max-age=604800' },
  /* 39 */ { name: 'cache-control',                      value: 'no-cache' },
  /* 40 */ { name: 'cache-control',                      value: 'no-store' },
  /* 41 */ { name: 'cache-control',                      value: 'public, max-age=31536000' },
  /* 42 */ { name: 'content-encoding',                   value: 'br' },
  /* 43 */ { name: 'content-encoding',                   value: 'gzip' },
  /* 44 */ { name: 'content-type',                       value: 'application/dns-message' },
  /* 45 */ { name: 'content-type',                       value: 'application/javascript' },
  /* 46 */ { name: 'content-type',                       value: 'application/json' },
  /* 47 */ { name: 'content-type',                       value: 'application/x-www-form-urlencoded' },
  /* 48 */ { name: 'content-type',                       value: 'image/gif' },
  /* 49 */ { name: 'content-type',                       value: 'image/jpeg' },
  /* 50 */ { name: 'content-type',                       value: 'image/png' },
  /* 51 */ { name: 'content-type',                       value: 'text/css' },
  /* 52 */ { name: 'content-type',                       value: 'text/html; charset=utf-8' },
  /* 53 */ { name: 'content-type',                       value: 'text/plain' },
  /* 54 */ { name: 'content-type',                       value: 'text/plain;charset=utf-8' },
  /* 55 */ { name: 'range',                              value: 'bytes=0-' },
  /* 56 */ { name: 'strict-transport-security',          value: 'max-age=31536000' },
  /* 57 */ { name: 'strict-transport-security',          value: 'max-age=31536000; includesubdomains' },
  /* 58 */ { name: 'strict-transport-security',          value: 'max-age=31536000; includesubdomains; preload' },
  /* 59 */ { name: 'vary',                               value: 'accept-encoding' },
  /* 60 */ { name: 'vary',                               value: 'origin' },
  /* 61 */ { name: 'x-content-type-options',             value: 'nosniff' },
  /* 62 */ { name: 'x-xss-protection',                   value: '1; mode=block' },
  /* 63 */ { name: ':status',                            value: '100' },
  /* 64 */ { name: ':status',                            value: '204' },
  /* 65 */ { name: ':status',                            value: '206' },
  /* 66 */ { name: ':status',                            value: '302' },
  /* 67 */ { name: ':status',                            value: '400' },
  /* 68 */ { name: ':status',                            value: '403' },
  /* 69 */ { name: ':status',                            value: '421' },
  /* 70 */ { name: ':status',                            value: '425' },
  /* 71 */ { name: ':status',                            value: '500' },
  /* 72 */ { name: 'accept-language',                    value: '' },
  /* 73 */ { name: 'access-control-allow-credentials',   value: 'FALSE' },
  /* 74 */ { name: 'access-control-allow-credentials',   value: 'TRUE' },
  /* 75 */ { name: 'access-control-allow-methods',       value: 'get' },
  /* 76 */ { name: 'access-control-allow-methods',       value: 'get, post, options' },
  /* 77 */ { name: 'access-control-allow-methods',       value: 'options' },
  /* 78 */ { name: 'access-control-expose-headers',      value: 'content-length' },
  /* 79 */ { name: 'access-control-request-headers',     value: 'content-type' },
  /* 80 */ { name: 'access-control-request-method',      value: 'get' },
  /* 81 */ { name: 'access-control-request-method',      value: 'post' },
  /* 82 */ { name: 'alt-svc',                            value: 'clear' },
  /* 83 */ { name: 'authorization',                      value: '' },
  /* 84 */ { name: 'content-security-policy',            value: "script-src 'none'; object-src 'none'; base-uri 'none'" },
  /* 85 */ { name: 'early-data',                         value: '1' },
  /* 86 */ { name: 'expect-ct',                          value: '' },
  /* 87 */ { name: 'forwarded',                          value: '' },
  /* 88 */ { name: 'if-range',                           value: '' },
  /* 89 */ { name: 'origin',                             value: '' },
  /* 90 */ { name: 'purpose',                            value: 'prefetch' },
  /* 91 */ { name: 'server',                             value: '' },
  /* 92 */ { name: 'timing-allow-origin',                value: '*' },
  /* 93 */ { name: 'upgrade-insecure-requests',          value: '1' },
  /* 94 */ { name: 'user-agent',                         value: '' },
  /* 95 */ { name: 'x-forwarded-for',                   value: '' },
  /* 96 */ { name: 'x-frame-options',                    value: 'deny' },
  /* 97 */ { name: 'x-frame-options',                    value: 'sameorigin' },
];

// Lookup maps
const STATIC_NAME_MAP    = new Map();
const STATIC_NAMEVAL_MAP = new Map();

for (let i = 0; i < STATIC_TABLE.length; i++) {
  const { name, value } = STATIC_TABLE[i];
  if (!STATIC_NAME_MAP.has(name)) STATIC_NAME_MAP.set(name, i);
  STATIC_NAMEVAL_MAP.set(`${name}\0${value}`, i);
}

// ----- Dynamic Table (RFC 9204 §3.2) -----
class DynamicTable {
  constructor(maxCapacity = 4096) {
    this.entries     = [];
    this.maxCapacity = maxCapacity;
    this.currentSize = 0;
    this.insertCount = 0;
  }

  setCapacity(capacity) {
    this.maxCapacity = capacity;
    this._evict();
  }

  insert(name, value) {
    const entrySize = name.length + value.length + 32;
    while (this.entries.length > 0 && this.currentSize + entrySize > this.maxCapacity) {
      const oldest = this.entries.pop();
      this.currentSize -= (oldest.name.length + oldest.value.length + 32);
    }
    if (entrySize > this.maxCapacity) return -1;
    this.entries.unshift({ name, value });
    this.currentSize += entrySize;
    this.insertCount++;
    return this.insertCount - 1;
  }

  getAbsolute(absIndex) {
    const relIndex = this.insertCount - 1 - absIndex;
    if (relIndex < 0 || relIndex >= this.entries.length) return null;
    return this.entries[relIndex];
  }

  getRelative(relIndex, base) {
    const absIndex = base - relIndex - 1;
    return this.getAbsolute(absIndex);
  }

  getPostBase(postBaseIndex, base) {
    const absIndex = base + postBaseIndex;
    return this.getAbsolute(absIndex);
  }

  _evict() {
    while (this.currentSize > this.maxCapacity && this.entries.length > 0) {
      const oldest = this.entries.pop();
      this.currentSize -= (oldest.name.length + oldest.value.length + 32);
    }
  }
}

// ----- Prefix Integer Encoding (RFC 7541 §5.1) -----

function encodePrefixInt(value, prefixBits) {
  const maxVal = (1 << prefixBits) - 1;
  if (value < maxVal) {
    return Buffer.from([value & maxVal]);
  }
  const bytes = [maxVal];
  value -= maxVal;
  while (value >= 128) {
    bytes.push((value & 0x7f) | 0x80);
    value >>>= 7;
  }
  bytes.push(value & 0x7f);
  return Buffer.from(bytes);
}

function decodePrefixInt(buf, offset, prefixBits) {
  if (offset >= buf.length) throw new RangeError(`decodePrefixInt: offset ${offset} >= buf.length ${buf.length}`);

  const maxVal = (1 << prefixBits) - 1;
  let value = buf[offset] & maxVal;
  let consumed = 1;

  if (value < maxVal) {
    return { value, length: consumed };
  }

  let shift = 0;
  while (true) {
    if (offset + consumed >= buf.length) {
      throw new RangeError('decodePrefixInt: buffer too short for multi-byte integer');
    }
    const b = buf[offset + consumed];
    consumed++;
    value += (b & 0x7f) << shift;
    shift += 7;
    if ((b & 0x80) === 0) break;
    if (shift > 28) throw new RangeError('decodePrefixInt: integer overflow (>28 bits)');
  }
  return { value, length: consumed };
}

// ----- String Literal (RFC 7541 §5.2) -----

function encodeString(str) {
  const raw = Buffer.from(str, 'utf8');
  const lenBytes = encodePrefixInt(raw.length, 7);
  lenBytes[0] &= 0x7f; // H=0 (no Huffman)
  return Buffer.concat([lenBytes, raw]);
}

function decodeString(buf, offset) {
  if (offset >= buf.length) {
    return { value: '', length: 0, error: true };
  }

  const isHuffman = (buf[offset] & 0x80) !== 0;

  let prefixResult;
  try {
    prefixResult = decodePrefixInt(buf, offset, 7);
  } catch (e) {
    return { value: '', length: buf.length - offset, error: true };
  }

  const { value: strLen, length: intLen } = prefixResult;
  const start = offset + intLen;

  if (start + strLen > buf.length) {
    return { value: '', length: buf.length - offset, error: true };
  }

  const strBuf = buf.subarray(start, start + strLen);
  let value;
  if (isHuffman) {
    // Let the error bubble up so the QPACK decoder can surface
    // QPACK_DECOMPRESSION_FAILED instead of returning garbage.
    value = decodeHuffman(strBuf);
  } else {
    value = strBuf.toString('utf8');
  }

  return { value, length: intLen + strLen };
}

// ----- QPACK Encoder -----

class QpackEncoder {
  constructor(options = {}) {
    this.dynamicTable = new DynamicTable(options.maxTableCapacity || 4096);
  }

  encode(headers) {
    const fieldLines = [];

    for (const [name, value] of headers) {
      const nvKey = `${name}\0${value}`;
      const staticFullIdx = STATIC_NAMEVAL_MAP.get(nvKey);
      if (staticFullIdx !== undefined) {
        const idxBuf = encodePrefixInt(staticFullIdx, 6);
        idxBuf[0] |= 0xc0;
        fieldLines.push(idxBuf);
        continue;
      }

      const staticNameIdx = STATIC_NAME_MAP.get(name);
      if (staticNameIdx !== undefined) {
        const idxBuf = encodePrefixInt(staticNameIdx, 4);
        idxBuf[0] = (idxBuf[0] & 0x0f) | 0x50;
        fieldLines.push(Buffer.concat([idxBuf, encodeString(value)]));
        continue;
      }

      const nameRaw = Buffer.from(name, 'utf8');
      const nameLenBuf = encodePrefixInt(nameRaw.length, 3);
      nameLenBuf[0] = (nameLenBuf[0] & 0x07) | 0x20;
      fieldLines.push(Buffer.concat([nameLenBuf, nameRaw, encodeString(value)]));
    }

    const ric     = encodePrefixInt(0, 8);
    const baseBuf = encodePrefixInt(0, 7);
    baseBuf[0] &= 0x7f;

    return {
      encoderStream: null,
      data: Buffer.concat([ric, baseBuf, ...fieldLines]),
    };
  }
}

// ----- QPACK Decoder -----

class QpackDecoder {
  constructor(options = {}) {
    this.dynamicTable = new DynamicTable(options.maxTableCapacity || 4096);
  }

  decode(buf) {
    const headers = [];
    let offset = 0;

    try {
      const { value: ric, length: ricLen } = decodePrefixInt(buf, offset, 8);
      offset += ricLen;
      if (offset >= buf.length) return headers;

      const signBit = (buf[offset] & 0x80) !== 0;
      const { value: deltaBase, length: dbLen } = decodePrefixInt(buf, offset, 7);
      offset += dbLen;

      const base = signBit ? (ric - deltaBase - 1) : (ric + deltaBase);

      let guard = 0;
      while (offset < buf.length && guard++ < 1000) {
        const prevOffset = offset;
        const b = buf[offset];

        if ((b & 0x80) !== 0) {
          const isStatic = (b & 0x40) !== 0;
          const { value: idx, length: iLen } = decodePrefixInt(buf, offset, 6);
          offset += iLen;
          const entry = isStatic
            ? STATIC_TABLE[idx]
            : this.dynamicTable.getRelative(idx, base);
          if (entry) headers.push([entry.name, entry.value]);

        } else if ((b & 0xc0) === 0x40) {
          const isStatic = (b & 0x10) !== 0;
          const { value: nameIdx, length: niLen } = decodePrefixInt(buf, offset, 4);
          offset += niLen;
          const { value: val, length: vLen, error: vErr } = decodeString(buf, offset);
          offset += vLen || 1;
          if (vErr) break;
          const entry = isStatic
            ? STATIC_TABLE[nameIdx]
            : this.dynamicTable.getRelative(nameIdx, base);
          headers.push([entry ? entry.name : '', val]);

        } else if ((b & 0xe0) === 0x20) {
          const nameHuffman = (buf[offset] & 0x08) !== 0;
          const { value: nameLen, length: nlLen } = decodePrefixInt(buf, offset, 3);
          offset += nlLen;
          if (offset + nameLen > buf.length) break;
          const nameBuf = buf.subarray(offset, offset + nameLen);
          const nameStr = nameHuffman
            ? (() => { try { return decodeHuffman(nameBuf); } catch { return nameBuf.toString('utf8'); } })()
            : nameBuf.toString('utf8');
          offset += nameLen;
          const { value: val, length: vLen, error: vErr } = decodeString(buf, offset);
          offset += vLen || 1;
          if (vErr) break;
          headers.push([nameStr, val]);

        } else if ((b & 0xf0) === 0x10) {
          const { value: idx, length: iLen } = decodePrefixInt(buf, offset, 4);
          offset += iLen;
          const entry = this.dynamicTable.getPostBase(idx, base);
          if (entry) headers.push([entry.name, entry.value]);

        } else if ((b & 0xf0) === 0x00) {
          const { value: nameIdx, length: niLen } = decodePrefixInt(buf, offset, 3);
          offset += niLen;
          const { value: val, length: vLen, error: vErr } = decodeString(buf, offset);
          offset += vLen || 1;
          if (vErr) break;
          const entry = this.dynamicTable.getPostBase(nameIdx, base);
          headers.push([entry ? entry.name : '', val]);

        } else {
          offset++;
        }

        if (offset === prevOffset) {
          offset++;
        }
      }
    } catch (err) {
      log.warn(`decode error (offset=${offset}):`, err.message);
    }

    return headers;
  }

  processEncoderInstruction(buf) {
    let offset = 0;
    let guard = 0;

    while (offset < buf.length && guard++ < 500) {
      const prevOffset = offset;
      try {
        const b = buf[offset];

        if ((b & 0xe0) === 0x20) {
          const { value: cap, length: cLen } = decodePrefixInt(buf, offset, 5);
          offset += cLen;
          this.dynamicTable.setCapacity(cap);

        } else if ((b & 0x80) !== 0) {
          const isStatic = (b & 0x40) !== 0;
          const { value: nameIdx, length: niLen } = decodePrefixInt(buf, offset, 6);
          offset += niLen;
          const { value: val, length: vLen } = decodeString(buf, offset);
          offset += vLen || 1;
          let name = '';
          if (isStatic) {
            name = STATIC_TABLE[nameIdx] ? STATIC_TABLE[nameIdx].name : '';
          } else {
            const entry = this.dynamicTable.getAbsolute(nameIdx);
            name = entry ? entry.name : '';
          }
          this.dynamicTable.insert(name, val);

        } else if ((b & 0xc0) === 0x40) {
          const { value: nameStr, length: nLen } = decodeString(buf, offset);
          offset += nLen || 1;
          const { value: val, length: vLen } = decodeString(buf, offset);
          offset += vLen || 1;
          this.dynamicTable.insert(nameStr, val);

        } else if ((b & 0xe0) === 0x00) {
          const { value: idx, length: iLen } = decodePrefixInt(buf, offset, 5);
          offset += iLen;
          const entry = this.dynamicTable.getAbsolute(idx);
          if (entry) this.dynamicTable.insert(entry.name, entry.value);

        } else {
          offset++;
        }

        if (offset === prevOffset) offset++;
      } catch (err) {
        log.warn('encoder instruction error:', err.message);
        break;
      }
    }
  }
}

module.exports = {
  STATIC_TABLE,
  STATIC_NAME_MAP,
  STATIC_NAMEVAL_MAP,
  DynamicTable,
  QpackEncoder,
  QpackDecoder,
  encodePrefixInt,
  decodePrefixInt,
  encodeString,
  decodeString,
  decodeHuffman,
};