'use strict';

const { createLogger } = require('../utils/logger');
const log = createLogger('QPACK');

// ----- Huffman Table (RFC 7541 Appendix B) -----
const HUFF_CODES = [
  0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
  0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
  0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
  0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
  0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa,
  0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
  0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
  0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
  0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
  0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
  0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
  0xfc, 0x73, 0xfd, 0x1ffb, 0x3ffe, 0x1ffc, 0x3ffc, 0x22,
  0x7ffd, 0x03, 0x23, 0x04, 0x24, 0x05, 0x25, 0x26,
  0x27, 0x06, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x07,
  0x2b, 0x76, 0x2c, 0x08, 0x09, 0x2d, 0x77, 0x78,
  0x79, 0x7a, 0x7b, 0xffc, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
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
  0x3fffffff,
];
const HUFF_LENGTHS = [
  13,23,28,28,28,28,28,28, 28,24,30,28,28,30,28,28, 28,28,28,28,28,28,30,28, 28,28,28,28,28,28,28,28,
   6,10,10,12,13, 6, 8,11, 10,10, 8,11, 8, 6, 6, 6,  5, 5, 5, 6, 6, 6, 6, 6,  6, 6, 7, 8,15, 6,12,10,
  13, 6, 7, 7, 7, 7, 7, 7,  7, 7, 7, 7, 7, 7, 7, 7,  7, 7, 7, 7, 7, 7, 7, 7,  8, 7, 8,13,14,13,14, 6,
  15, 5, 6, 5, 6, 5, 6, 6,  6, 5, 7, 7, 6, 6, 6, 5,  6, 7, 6, 5, 5, 6, 7, 7,  7, 7, 7,12,11,14,13,28,
  20,22,20,20,22,22,22,23, 22,23,23,23,23,23,24,23, 24,24,22,23,24,23,23,23, 23,21,22,23,22,23,23,24,
  22,21,20,22,22,23,23,21, 23,22,22,24,21,22,23,23, 21,21,22,21,23,22,23,23, 20,22,22,22,23,22,22,23,
  26,26,20,19,22,23,22,25, 26,26,26,27,27,26,24,25, 19,21,26,27,27,26,27,24, 21,21,26,26,28,27,27,27,
  20,24,20,21,22,21,21,23, 22,22,25,25,24,24,26,23, 26,27,26,26,27,27,27,27, 27,28,27,27,27,27,27,26,
  30,
];

let _huffmanRoot = null;
function _buildTree() {
  if (_huffmanRoot) return _huffmanRoot;
  const root = {};
  for (let sym = 0; sym < HUFF_CODES.length; sym++) {
    const code = HUFF_CODES[sym], len = HUFF_LENGTHS[sym];
    let node = root;
    for (let bit = len - 1; bit >= 0; bit--) {
      const go = (code >>> bit) & 1;
      if (go) { if (!node.r) node.r = {}; node = node.r; } 
      else { if (!node.l) node.l = {}; node = node.l; }
    }
    node.sym = sym;
  }
  _huffmanRoot = root; return root;
}

function decodeHuffman(buf) {
  const root = _buildTree();
  const out  = [];
  let node   = root, tailBits = 0, tailVal  = 0;
  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i];
    for (let bit = 7; bit >= 0; bit--) {
      const b = (byte >>> bit) & 1;
      node = b ? node.r : node.l;
      if (!node) throw new Error('QPACK Huffman: invalid code path');
      tailVal = (tailVal << 1) | b; tailBits++;
      if (node.sym !== undefined) {
        if (node.sym === 256) throw new Error('QPACK Huffman: EOS symbol in stream');
        out.push(node.sym);
        node = root; tailBits = 0; tailVal = 0;
      }
    }
  }
  return Buffer.from(out).toString('utf8');
}

// EKSİKSİZ VE STANDART UYUMLU RFC 9204 STATIC TABLE
const STATIC_TABLE = [
  { name: ':authority', value: '' },
  { name: ':path', value: '/' },
  { name: 'age', value: '0' },
  { name: 'content-disposition', value: '' },
  { name: 'content-length', value: '0' },
  { name: 'cookie', value: '' },
  { name: 'date', value: '' },
  { name: 'etag', value: '' },
  { name: 'if-modified-since', value: '' },
  { name: 'if-none-match', value: '' },
  { name: 'last-modified', value: '' },
  { name: 'link', value: '' },
  { name: 'location', value: '' },
  { name: 'referer', value: '' },
  { name: 'set-cookie', value: '' },
  { name: ':method', value: 'CONNECT' },
  { name: ':method', value: 'DELETE' },
  { name: ':method', value: 'GET' },
  { name: ':method', value: 'HEAD' },
  { name: ':method', value: 'OPTIONS' },
  { name: ':method', value: 'POST' },
  { name: ':method', value: 'PUT' },
  { name: ':scheme', value: 'http' },
  { name: ':scheme', value: 'https' },
  { name: ':status', value: '103' },
  { name: ':status', value: '200' },
  { name: ':status', value: '304' },
  { name: ':status', value: '404' },
  { name: ':status', value: '503' },
  { name: 'accept', value: '*/*' },
  { name: 'accept', value: 'application/dns-message' },
  { name: 'accept-encoding', value: 'gzip, deflate, br' },
  { name: 'accept-ranges', value: 'bytes' },
  { name: 'access-control-allow-headers', value: 'cache-control' },
  { name: 'access-control-allow-headers', value: 'content-type' },
  { name: 'access-control-allow-origin', value: '*' },
  { name: 'cache-control', value: 'max-age=0' },
  { name: 'cache-control', value: 'max-age=2592000' },
  { name: 'cache-control', value: 'max-age=604800' },
  { name: 'cache-control', value: 'no-cache' },
  { name: 'cache-control', value: 'no-store' },
  { name: 'cache-control', value: 'public, max-age=31536000' },
  { name: 'content-encoding', value: 'br' },
  { name: 'content-encoding', value: 'gzip' },
  { name: 'content-type', value: 'application/dns-message' },
  { name: 'content-type', value: 'application/javascript' },
  { name: 'content-type', value: 'application/json' },
  { name: 'content-type', value: 'application/x-www-form-urlencoded' },
  { name: 'content-type', value: 'image/gif' },
  { name: 'content-type', value: 'image/jpeg' },
  { name: 'content-type', value: 'image/png' },
  { name: 'content-type', value: 'text/css' },
  { name: 'content-type', value: 'text/html; charset=utf-8' },
  { name: 'content-type', value: 'text/plain' },
  { name: 'content-type', value: 'text/plain;charset=utf-8' },
  { name: 'range', value: 'bytes=0-' },
  { name: 'strict-transport-security', value: 'max-age=31536000' },
  { name: 'strict-transport-security', value: 'max-age=31536000; includesubdomains' },
  { name: 'strict-transport-security', value: 'max-age=31536000; includesubdomains; preload' },
  { name: 'vary', value: 'accept-encoding' },
  { name: 'vary', value: 'origin' },
  { name: 'x-content-type-options', value: 'nosniff' },
  { name: 'x-xss-protection', value: '1; mode=block' },
  { name: ':status', value: '100' },
  { name: ':status', value: '204' },
  { name: ':status', value: '206' },
  { name: ':status', value: '302' },
  { name: ':status', value: '400' },
  { name: ':status', value: '403' },
  { name: ':status', value: '421' },
  { name: ':status', value: '425' },
  { name: ':status', value: '500' },
  { name: 'accept-language', value: '' },
  { name: 'access-control-allow-credentials', value: 'FALSE' },
  { name: 'access-control-allow-credentials', value: 'TRUE' },
  { name: 'access-control-allow-headers', value: '' }, // <--- İŞTE UNUTULAN KRİTİK SATIR BURASIYDI! (Index 75)
  { name: 'access-control-allow-methods', value: 'get' },
  { name: 'access-control-allow-methods', value: 'get, post, options' },
  { name: 'access-control-allow-methods', value: 'options' },
  { name: 'access-control-expose-headers', value: 'content-length' },
  { name: 'access-control-request-headers', value: 'content-type' },
  { name: 'access-control-request-method', value: 'get' },
  { name: 'access-control-request-method', value: 'post' },
  { name: 'alt-svc', value: 'clear' },
  { name: 'authorization', value: '' },
  { name: 'content-security-policy', value: "script-src 'none'; object-src 'none'; base-uri 'none'" },
  { name: 'early-data', value: '1' },
  { name: 'expect-ct', value: '' },
  { name: 'forwarded', value: '' },
  { name: 'if-range', value: '' },
  { name: 'origin', value: '' },
  { name: 'purpose', value: 'prefetch' },
  { name: 'server', value: '' },
  { name: 'timing-allow-origin', value: '*' },
  { name: 'upgrade-insecure-requests', value: '1' },
  { name: 'user-agent', value: '' },
  { name: 'x-forwarded-for', value: '' },
  { name: 'x-frame-options', value: 'deny' },
  { name: 'x-frame-options', value: 'sameorigin' }
];

const STATIC_NAME_MAP = new Map();
const STATIC_NAMEVAL_MAP = new Map();
for (let i = 0; i < STATIC_TABLE.length; i++) {
  const { name, value } = STATIC_TABLE[i];
  if (!STATIC_NAME_MAP.has(name)) STATIC_NAME_MAP.set(name, i);
  STATIC_NAMEVAL_MAP.set(`${name}\0${value}`, i);
}

class DynamicTable {
  constructor(maxCapacity = 4096) {
    this.entries = [];
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

function encodePrefixInt(value, prefixBits) {
  const maxVal = (1 << prefixBits) - 1;
  if (value < maxVal) return Buffer.from([value & maxVal]);
  const bytes = [maxVal];
  value -= maxVal;
  while (value >= 128) { bytes.push((value & 0x7f) | 0x80); value >>>= 7; }
  bytes.push(value & 0x7f);
  return Buffer.from(bytes);
}

function decodePrefixInt(buf, offset, prefixBits) {
  if (offset >= buf.length) throw new RangeError('Buffer too short');
  const maxVal = (1 << prefixBits) - 1;
  let value = buf[offset] & maxVal;
  let consumed = 1;
  if (value < maxVal) return { value, length: consumed };

  let shift = 0;
  while (true) {
    if (offset + consumed >= buf.length) throw new RangeError('Buffer too short');
    const b = buf[offset + consumed];
    consumed++;
    value += (b & 0x7f) << shift;
    shift += 7;
    if ((b & 0x80) === 0) break;
  }
  return { value, length: consumed };
}

function decodeString(buf, offset, prefixBits = 7) {
  if (offset >= buf.length) {
    return { value: '', length: 0, error: true };
  }
  const isHuffman = (buf[offset] & (1 << prefixBits)) !== 0;
  let prefixResult;
  try {
    prefixResult = decodePrefixInt(buf, offset, prefixBits);
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
    try { value = decodeHuffman(strBuf); } catch (e) { 
      value = strBuf.toString('utf8'); 
    }
  } else {
    value = strBuf.toString('utf8');
  }
  return { value, length: intLen + strLen };
}

function encodeString(str) {
  const raw = Buffer.from(str, 'utf8');
  const lenBytes = encodePrefixInt(raw.length, 7);
  lenBytes[0] &= 0x7f; 
  return Buffer.concat([lenBytes, raw]);
}

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
        idxBuf[0] |= 0xc0; fieldLines.push(idxBuf); continue;
      }
      const staticNameIdx = STATIC_NAME_MAP.get(name);
      if (staticNameIdx !== undefined) {
        const idxBuf = encodePrefixInt(staticNameIdx, 4);
        idxBuf[0] = (idxBuf[0] & 0x0f) | 0x50;
        fieldLines.push(Buffer.concat([idxBuf, encodeString(value)])); continue;
      }
      const nameRaw = Buffer.from(name, 'utf8');
      const nameLenBuf = encodePrefixInt(nameRaw.length, 3);
      nameLenBuf[0] = (nameLenBuf[0] & 0x07) | 0x20;
      fieldLines.push(Buffer.concat([nameLenBuf, nameRaw, encodeString(value)]));
    }
    const ric = encodePrefixInt(0, 8);
    const baseBuf = encodePrefixInt(0, 7);
    baseBuf[0] &= 0x7f;
    return { encoderStream: null, data: Buffer.concat([ric, baseBuf, ...fieldLines]) };
  }
}

class QpackDecoder {
  constructor(options = {}) {
    this.dynamicTable = new DynamicTable(options.maxTableCapacity || 4096);
  }

  decode(buf) {
    const headers = [];
    let offset = 0;
    try {
      const { value: rawRic, length: ricLen } = decodePrefixInt(buf, offset, 8);
      offset += ricLen;
      if (offset >= buf.length) return headers;

      const signBit = (buf[offset] & 0x80) !== 0;
      const { value: deltaBase, length: dbLen } = decodePrefixInt(buf, offset, 7);
      offset += dbLen;

      let ric = rawRic === 0 ? 0 : rawRic - 1;
      const base = signBit ? (ric - deltaBase - 1) : (ric + deltaBase);

      let guard = 0;
      while (offset < buf.length && guard++ < 2000) {
        const prevOffset = offset;
        const b = buf[offset];
        
        if ((b & 0x80) !== 0) {
          const isStatic = (b & 0x40) !== 0;
          const { value: idx, length: iLen } = decodePrefixInt(buf, offset, 6);
          offset += iLen;
          const entry = isStatic ? STATIC_TABLE[idx] : this.dynamicTable.getRelative(idx, base);
          if (entry) {
            headers.push([entry.name, entry.value]);
          }

        } else if ((b & 0xc0) === 0x40) {
          const isStatic = (b & 0x10) !== 0;
          const { value: nameIdx, length: niLen } = decodePrefixInt(buf, offset, 4);
          offset += niLen;
          const { value: val, length: vLen, error: vErr } = decodeString(buf, offset, 7);
          offset += vLen || 1;
          if (vErr) break;
          const entry = isStatic ? STATIC_TABLE[nameIdx] : this.dynamicTable.getRelative(nameIdx, base);
          
          if (entry) {
            headers.push([entry.name, val]);
          } else {
            headers.push(['', val]);
          }

        } else if ((b & 0xe0) === 0x20) {
          const { value: nameStr, length: nLen, error: nErr } = decodeString(buf, offset, 3);
          offset += nLen || 1;
          if (nErr) break;
          
          const { value: val, length: vLen, error: vErr } = decodeString(buf, offset, 7);
          offset += vLen || 1;
          if (vErr) break;
          
          headers.push([nameStr, val]);

        } else if ((b & 0xf0) === 0x10) {
          const { value: idx, length: iLen } = decodePrefixInt(buf, offset, 4);
          offset += iLen;
          const entry = this.dynamicTable.getPostBase(idx, base);
          if (entry) {
            headers.push([entry.name, entry.value]);
          }

        } else if ((b & 0xf0) === 0x00) {
          const { value: nameIdx, length: niLen } = decodePrefixInt(buf, offset, 3);
          offset += niLen;
          const { value: val, length: vLen, error: vErr } = decodeString(buf, offset, 7);
          offset += vLen || 1;
          if (vErr) break;
          const entry = this.dynamicTable.getPostBase(nameIdx, base);
          
          if (entry) {
            headers.push([entry.name, val]);
          } else {
             headers.push(['', val]);
          }

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
    if (!this._encBuf) this._encBuf = Buffer.alloc(0);
    this._encBuf = Buffer.concat([this._encBuf, buf]);

    let offset = 0;
    let guard = 0;

    while (offset < this._encBuf.length && guard++ < 500) {
      const prevOffset = offset;
      try {
        const b = this._encBuf[offset];

        if ((b & 0xe0) === 0x20) {
          const { value: cap, length: cLen } = decodePrefixInt(this._encBuf, offset, 5);
          offset += cLen;
          this.dynamicTable.setCapacity(cap);

        } else if ((b & 0x80) !== 0) {
          const isStatic = (b & 0x40) !== 0;
          const { value: nameIdx, length: niLen } = decodePrefixInt(this._encBuf, offset, 6);
          offset += niLen;
          const { value: val, length: vLen, error } = decodeString(this._encBuf, offset, 7);
          if (error) throw new Error('incomplete');
          offset += vLen;
          
          let name = '';
          if (isStatic) {
            name = STATIC_TABLE[nameIdx] ? STATIC_TABLE[nameIdx].name : '';
          } else {
            const entry = this.dynamicTable.getRelative(nameIdx, this.dynamicTable.insertCount);
            name = entry ? entry.name : '';
          }
          this.dynamicTable.insert(name, val);

        } else if ((b & 0xc0) === 0x40) {
          const { value: nameStr, length: nLen, error: nErr } = decodeString(this._encBuf, offset, 5);
          if (nErr) throw new Error('incomplete');
          offset += nLen;
          
          const { value: val, length: vLen, error: vErr } = decodeString(this._encBuf, offset, 7);
          if (vErr) throw new Error('incomplete');
          offset += vLen;
          this.dynamicTable.insert(nameStr, val);

        } else if ((b & 0xe0) === 0x00) {
          const { value: idx, length: iLen } = decodePrefixInt(this._encBuf, offset, 5);
          offset += iLen;
          const entry = this.dynamicTable.getRelative(idx, this.dynamicTable.insertCount);
          if (entry) {
            this.dynamicTable.insert(entry.name, entry.value);
          } else {
            this.dynamicTable.insert('err-dup', ''); 
          }

        } else {
          offset++;
        }

        if (offset === prevOffset) offset++;
      } catch (err) {
        offset = prevOffset; 
        break; 
      }
    }
    this._encBuf = this._encBuf.subarray(offset);
  }

  _unblockStreams() {
    if (!this._blockedStreams) return;
    for (const [sid, entry] of this._blockedStreams) {
      if (this.decoder.dynamicTable.insertCount >= entry.requiredInserts) {
        this._blockedStreams.delete(sid);
        try { entry.request._handleFrame(entry.pendingFrame); } catch {}
      }
    }
  }
}

module.exports = {
  QPACK_STATIC_TABLE: STATIC_TABLE,
  STATIC_NAME_MAP,
  STATIC_NAMEVAL_MAP,
  QPACK_DYNAMIC_TABLE: DynamicTable,
  QpackEncoder,
  QpackDecoder,
  encodePrefixInt,
  decodePrefixInt,
  encodeString,
  decodeString,
  decodeHuffman,
};