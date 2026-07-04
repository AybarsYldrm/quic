'use strict';

// ====================================================================
// 1. STATIC TABLE (RFC 7541 Appendix A)
// ====================================================================

const STATIC_TABLE = [
  null, // index 0 unused
  [':authority', ''],
  [':method', 'GET'],
  [':method', 'POST'],
  [':path', '/'],
  [':path', '/index.html'],
  [':scheme', 'http'],
  [':scheme', 'https'],
  [':status', '200'],
  [':status', '204'],
  [':status', '206'],
  [':status', '304'],
  [':status', '400'],
  [':status', '404'],
  [':status', '500'],
  ['accept-charset', ''],
  ['accept-encoding', 'gzip, deflate'],
  ['accept-language', ''],
  ['accept-ranges', ''],
  ['accept', ''],
  ['access-control-allow-origin', ''],
  ['age', ''],
  ['allow', ''],
  ['authorization', ''],
  ['cache-control', ''],
  ['content-disposition', ''],
  ['content-encoding', ''],
  ['content-language', ''],
  ['content-length', ''],
  ['content-location', ''],
  ['content-range', ''],
  ['content-type', ''],
  ['cookie', ''],
  ['date', ''],
  ['etag', ''],
  ['expect', ''],
  ['expires', ''],
  ['from', ''],
  ['host', ''],
  ['if-match', ''],
  ['if-modified-since', ''],
  ['if-none-match', ''],
  ['if-range', ''],
  ['if-unmodified-since', ''],
  ['last-modified', ''],
  ['link', ''],
  ['location', ''],
  ['max-forwards', ''],
  ['proxy-authenticate', ''],
  ['proxy-authorization', ''],
  ['range', ''],
  ['referer', ''],
  ['refresh', ''],
  ['retry-after', ''],
  ['server', ''],
  ['set-cookie', ''],
  ['strict-transport-security', ''],
  ['transfer-encoding', ''],
  ['user-agent', ''],
  ['vary', ''],
  ['via', ''],
  ['www-authenticate', ''],
];

const STATIC_NAME_INDEX = new Map();
const STATIC_FULL_INDEX = new Map();

for (let i = 1; i < STATIC_TABLE.length; i++) {
  const [name, value] = STATIC_TABLE[i];
  const fullKey = `${name}\0${value}`;

  if (!STATIC_NAME_INDEX.has(name)) {
    STATIC_NAME_INDEX.set(name, i);
  }
  if (value && !STATIC_FULL_INDEX.has(fullKey)) {
    STATIC_FULL_INDEX.set(fullKey, i);
  }
}

// ====================================================================
// 2. HUFFMAN CODING (RFC 7541 Appendix B)
// ====================================================================

const HUFFMAN_TABLE = [
  { code: 0x1ff8, bits: 13 },     { code: 0x7fffd8, bits: 23 },   { code: 0xfffffe2, bits: 28 },  { code: 0xfffffe3, bits: 28 },
  { code: 0xfffffe4, bits: 28 },  { code: 0xfffffe5, bits: 28 },  { code: 0xfffffe6, bits: 28 },  { code: 0xfffffe7, bits: 28 },
  { code: 0xfffffe8, bits: 28 },  { code: 0xffffea, bits: 24 },   { code: 0x3ffffffc, bits: 30 }, { code: 0xfffffe9, bits: 28 },
  { code: 0xfffffea, bits: 28 },  { code: 0x3ffffffd, bits: 30 }, { code: 0xfffffeb, bits: 28 },  { code: 0xfffffec, bits: 28 },
  { code: 0xfffffed, bits: 28 },  { code: 0xfffffee, bits: 28 },  { code: 0xfffffef, bits: 28 },  { code: 0xffffff0, bits: 28 },
  { code: 0xffffff1, bits: 28 },  { code: 0xffffff2, bits: 28 },  { code: 0x3ffffffe, bits: 30 }, { code: 0xffffff3, bits: 28 },
  { code: 0xffffff4, bits: 28 },  { code: 0xffffff5, bits: 28 },  { code: 0xffffff6, bits: 28 },  { code: 0xffffff7, bits: 28 },
  { code: 0xffffff8, bits: 28 },  { code: 0xffffff9, bits: 28 },  { code: 0xffffffa, bits: 28 },  { code: 0xffffffb, bits: 28 },
  { code: 0x14, bits: 6 },        { code: 0x3f8, bits: 10 },      { code: 0x3f9, bits: 10 },      { code: 0xffa, bits: 12 },
  { code: 0x1ff9, bits: 13 },     { code: 0x15, bits: 6 },        { code: 0xf8, bits: 8 },        { code: 0x7fa, bits: 11 },
  { code: 0x3fa, bits: 10 },      { code: 0x3fb, bits: 10 },      { code: 0xf9, bits: 8 },        { code: 0x7fb, bits: 11 },
  { code: 0xfa, bits: 8 },        { code: 0x16, bits: 6 },        { code: 0x17, bits: 6 },        { code: 0x18, bits: 6 },
  { code: 0x0, bits: 5 },         { code: 0x1, bits: 5 },         { code: 0x2, bits: 5 },         { code: 0x19, bits: 6 },
  { code: 0x1a, bits: 6 },        { code: 0x1b, bits: 6 },        { code: 0x1c, bits: 6 },        { code: 0x1d, bits: 6 },
  { code: 0x1e, bits: 6 },        { code: 0x1f, bits: 6 },        { code: 0x5c, bits: 7 },        { code: 0xfb, bits: 8 },
  { code: 0x7ffc, bits: 15 },     { code: 0x20, bits: 6 },        { code: 0xffb, bits: 12 },      { code: 0x3fc, bits: 10 },
  { code: 0x1ffa, bits: 13 },     { code: 0x21, bits: 6 },        { code: 0x5d, bits: 7 },        { code: 0x5e, bits: 7 },
  { code: 0x5f, bits: 7 },        { code: 0x60, bits: 7 },        { code: 0x61, bits: 7 },        { code: 0x62, bits: 7 },
  { code: 0x63, bits: 7 },        { code: 0x64, bits: 7 },        { code: 0x65, bits: 7 },        { code: 0x66, bits: 7 },
  { code: 0x67, bits: 7 },        { code: 0x68, bits: 7 },        { code: 0x69, bits: 7 },        { code: 0x6a, bits: 7 },
  { code: 0x6b, bits: 7 },        { code: 0x6c, bits: 7 },        { code: 0x6d, bits: 7 },        { code: 0x6e, bits: 7 },
  { code: 0x6f, bits: 7 },        { code: 0x70, bits: 7 },        { code: 0x71, bits: 7 },        { code: 0x72, bits: 7 },
  { code: 0xfc, bits: 8 },        { code: 0x73, bits: 7 },        { code: 0xfd, bits: 8 },        { code: 0x1ffb, bits: 13 },
  { code: 0x7fff0, bits: 19 },    { code: 0x1ffc, bits: 13 },     { code: 0x3ffc, bits: 14 },     { code: 0x22, bits: 6 },
  { code: 0x7ffd, bits: 15 },     { code: 0x3, bits: 5 },         { code: 0x23, bits: 6 },        { code: 0x4, bits: 5 },
  { code: 0x24, bits: 6 },        { code: 0x5, bits: 5 },         { code: 0x25, bits: 6 },        { code: 0x26, bits: 6 },
  { code: 0x27, bits: 6 },        { code: 0x6, bits: 5 },         { code: 0x74, bits: 7 },        { code: 0x75, bits: 7 },
  { code: 0x28, bits: 6 },        { code: 0x29, bits: 6 },        { code: 0x2a, bits: 6 },        { code: 0x7, bits: 5 },
  { code: 0x2b, bits: 6 },        { code: 0x76, bits: 7 },        { code: 0x2c, bits: 6 },        { code: 0x8, bits: 5 },
  { code: 0x9, bits: 5 },         { code: 0x2d, bits: 6 },        { code: 0x77, bits: 7 },        { code: 0x78, bits: 7 },
  { code: 0x79, bits: 7 },        { code: 0x7a, bits: 7 },        { code: 0x7b, bits: 7 },        { code: 0x7fffe, bits: 19 },
  { code: 0x7fc, bits: 11 },      { code: 0x3ffd, bits: 14 },     { code: 0x1ffd, bits: 13 },     { code: 0xffffffc, bits: 28 },
  { code: 0xfffe6, bits: 20 },    { code: 0x3fffd2, bits: 22 },   { code: 0xfffe7, bits: 20 },    { code: 0xfffe8, bits: 20 },
  { code: 0x3fffd3, bits: 22 },   { code: 0x3fffd4, bits: 22 },   { code: 0x3fffd5, bits: 22 },   { code: 0x7fffd9, bits: 23 },
  { code: 0x3fffd6, bits: 22 },   { code: 0x7fffda, bits: 23 },   { code: 0x7fffdb, bits: 23 },   { code: 0x7fffdc, bits: 23 },
  { code: 0x7fffdd, bits: 23 },   { code: 0x7fffde, bits: 23 },   { code: 0xffffeb, bits: 24 },   { code: 0x7fffdf, bits: 23 },
  { code: 0xffffec, bits: 24 },   { code: 0xffffed, bits: 24 },   { code: 0x3fffd7, bits: 22 },   { code: 0x7fffe0, bits: 23 },
  { code: 0xffffee, bits: 24 },   { code: 0x7fffe1, bits: 23 },   { code: 0x7fffe2, bits: 23 },   { code: 0x7fffe3, bits: 23 },
  { code: 0x7fffe4, bits: 23 },   { code: 0x1fffdc, bits: 21 },   { code: 0x3fffd8, bits: 22 },   { code: 0x7fffe5, bits: 23 },
  { code: 0x3fffd9, bits: 22 },   { code: 0x7fffe6, bits: 23 },   { code: 0x7fffe7, bits: 23 },   { code: 0xffffef, bits: 24 },
  { code: 0x3fffda, bits: 22 },   { code: 0x1fffdd, bits: 21 },   { code: 0xfffe9, bits: 20 },    { code: 0x3fffdb, bits: 22 },
  { code: 0x3fffdc, bits: 22 },   { code: 0x7fffe8, bits: 23 },   { code: 0x7fffe9, bits: 23 },   { code: 0x1fffde, bits: 21 },
  { code: 0x7fffea, bits: 23 },   { code: 0x3fffdd, bits: 22 },   { code: 0x3fffde, bits: 22 },   { code: 0xfffff0, bits: 24 },
  { code: 0x1fffdf, bits: 21 },   { code: 0x3fffdf, bits: 22 },   { code: 0x7fffeb, bits: 23 },   { code: 0x7fffec, bits: 23 },
  { code: 0x1fffe0, bits: 21 },   { code: 0x1fffe1, bits: 21 },   { code: 0x3fffe0, bits: 22 },   { code: 0x1fffe2, bits: 21 },
  { code: 0x7fffed, bits: 23 },   { code: 0x3fffe1, bits: 22 },   { code: 0x7fffee, bits: 23 },   { code: 0x7fffef, bits: 23 },
  { code: 0xfffea, bits: 20 },    { code: 0x3fffe2, bits: 22 },   { code: 0x3fffe3, bits: 22 },   { code: 0x3fffe4, bits: 22 },
  { code: 0x7ffff0, bits: 23 },   { code: 0x3fffe5, bits: 22 },   { code: 0x3fffe6, bits: 22 },   { code: 0x7ffff1, bits: 23 },
  { code: 0x3ffffe0, bits: 26 },  { code: 0x3ffffe1, bits: 26 },  { code: 0xfffeb, bits: 20 },    { code: 0x7fff1, bits: 19 },
  { code: 0x3fffe7, bits: 22 },   { code: 0x7ffff2, bits: 23 },   { code: 0x3fffe8, bits: 22 },   { code: 0x1ffffec, bits: 25 },
  { code: 0x3ffffe2, bits: 26 },  { code: 0x3ffffe3, bits: 26 },  { code: 0x3ffffe4, bits: 26 },  { code: 0x7ffffde, bits: 27 },
  { code: 0x7ffffdf, bits: 27 },  { code: 0x3ffffe5, bits: 26 },  { code: 0xfffff1, bits: 24 },   { code: 0x1ffffed, bits: 25 },
  { code: 0x7fff2, bits: 19 },    { code: 0x1fffe3, bits: 21 },   { code: 0x3ffffe6, bits: 26 },  { code: 0x7ffffe0, bits: 27 },
  { code: 0x7ffffe1, bits: 27 },  { code: 0x3ffffe7, bits: 26 },  { code: 0x7ffffe2, bits: 27 },  { code: 0xfffff2, bits: 24 },
  { code: 0x1fffe4, bits: 21 },   { code: 0x1fffe5, bits: 21 },   { code: 0x3ffffe8, bits: 26 },  { code: 0x3ffffe9, bits: 26 },
  { code: 0xffffffd, bits: 28 },  { code: 0x7ffffe3, bits: 27 },  { code: 0x7ffffe4, bits: 27 },  { code: 0x7ffffe5, bits: 27 },
  { code: 0xfffec, bits: 20 },    { code: 0xfffff3, bits: 24 },   { code: 0xfffed, bits: 20 },    { code: 0x1fffe6, bits: 21 },
  { code: 0x3fffe9, bits: 22 },   { code: 0x1fffe7, bits: 21 },   { code: 0x1fffe8, bits: 21 },   { code: 0x7ffff3, bits: 23 },
  { code: 0x3fffea, bits: 22 },   { code: 0x3fffeb, bits: 22 },   { code: 0x1ffffee, bits: 25 },  { code: 0x1ffffef, bits: 25 },
  { code: 0xfffff4, bits: 24 },   { code: 0xfffff5, bits: 24 },   { code: 0x3ffffea, bits: 26 },  { code: 0x7ffff4, bits: 23 },
  { code: 0x3ffffeb, bits: 26 },  { code: 0x7ffffe6, bits: 27 },  { code: 0x3ffffec, bits: 26 },  { code: 0x3ffffed, bits: 26 },
  { code: 0x7ffffe7, bits: 27 },  { code: 0x7ffffe8, bits: 27 },  { code: 0x7ffffe9, bits: 27 },  { code: 0x7ffffea, bits: 27 },
  { code: 0x7ffffeb, bits: 27 },  { code: 0xfffffffe, bits: 30 }, { code: 0x7ffffec, bits: 27 },  { code: 0x7ffffed, bits: 27 },
  { code: 0x7ffffee, bits: 27 },  { code: 0x7ffffef, bits: 27 },  { code: 0x7fffff0, bits: 27 },  { code: 0x3ffffee, bits: 26 },
  { code: 0x3fffffff, bits: 30 }, // 256 EOS
];

function huffmanEncode(input) {
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input, 'ascii');
  let totalBits = 0;
  for (let i = 0; i < bytes.length; i++) totalBits += HUFFMAN_TABLE[bytes[i]].bits;

  const output = Buffer.alloc(Math.ceil(totalBits / 8));
  let bitPos = 0;

  for (let i = 0; i < bytes.length; i++) {
    const { code, bits } = HUFFMAN_TABLE[bytes[i]];
    let remaining = bits;
    while (remaining > 0) {
      const byteIdx = bitPos >> 3;
      const bitIdx = bitPos & 7;
      const available = 8 - bitIdx;
      const toWrite = Math.min(available, remaining);

      const shift = remaining - toWrite;
      const mask = ((1 << toWrite) - 1);
      const value = (code >> shift) & mask;

      output[byteIdx] |= value << (available - toWrite);
      bitPos += toWrite;
      remaining -= toWrite;
    }
  }

  const padBits = (8 - (bitPos & 7)) & 7;
  if (padBits > 0) {
    const byteIdx = bitPos >> 3;
    output[byteIdx] |= (1 << padBits) - 1;
  }

  return output;
}

function buildDecodeTree() {
  const root = {};
  for (let sym = 0; sym < 257; sym++) {
    const { code, bits } = HUFFMAN_TABLE[sym];
    let node = root;
    for (let i = bits - 1; i >= 0; i--) {
      const bit = (code >> i) & 1;
      if (!node[bit]) node[bit] = i === 0 ? { symbol: sym } : {};
      node = node[bit];
    }
  }
  return root;
}
const DECODE_TREE = buildDecodeTree();

function huffmanDecode(data) {
  const output = [];
  let node = DECODE_TREE;
  for (let byteIdx = 0; byteIdx < data.length; byteIdx++) {
    for (let bitIdx = 7; bitIdx >= 0; bitIdx--) {
      const bit = (data[byteIdx] >> bitIdx) & 1;
      node = node[bit];
      if (!node) throw new Error('Invalid Huffman encoding');
      if ('symbol' in node) {
        if (node.symbol === 256) return Buffer.from(output); // EOS
        output.push(node.symbol);
        node = DECODE_TREE;
      }
    }
  }
  return Buffer.from(output);
}

function huffmanEncodedLength(input) {
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input, 'ascii');
  let totalBits = 0;
  for (let i = 0; i < bytes.length; i++) totalBits += HUFFMAN_TABLE[bytes[i]].bits;
  return Math.ceil(totalBits / 8);
}

// ====================================================================
// 3. DYNAMIC TABLE
// ====================================================================

const ENTRY_OVERHEAD = 32;

class DynamicTable {
  constructor(maxSize = 4096) {
    this.entries = [];
    this.maxSize = maxSize;
    this.currentSize = 0;
  }

  add(name, value) {
    const entrySize = name.length + value.length + ENTRY_OVERHEAD;
    while (this.currentSize + entrySize > this.maxSize && this.entries.length > 0) this._evict();
    if (entrySize > this.maxSize) {
      this.entries = [];
      this.currentSize = 0;
      return;
    }
    this.entries.unshift([name, value]);
    this.currentSize += entrySize;
  }

  get(index) {
    if (index < 0 || index >= this.entries.length) return null;
    return this.entries[index];
  }

  absoluteIndex(dynamicIndex) { return 62 + dynamicIndex; }

  find(name, value) {
    for (let i = 0; i < this.entries.length; i++) {
      if (this.entries[i][0] === name && this.entries[i][1] === value) return i;
    }
    return -1;
  }

  findName(name) {
    for (let i = 0; i < this.entries.length; i++) {
      if (this.entries[i][0] === name) return i;
    }
    return -1;
  }

  setMaxSize(newMax) {
    this.maxSize = newMax;
    while (this.currentSize > this.maxSize && this.entries.length > 0) this._evict();
  }

  _evict() {
    const entry = this.entries.pop();
    if (entry) this.currentSize -= entry[0].length + entry[1].length + ENTRY_OVERHEAD;
  }

  get length() { return this.entries.length; }
}

// ====================================================================
// 4. ENCODE / DECODE UTILITIES
// ====================================================================

function encodeInteger(value, prefixBits, flags) {
  const maxPrefix = (1 << prefixBits) - 1;
  if (value < maxPrefix) return Buffer.from([flags | value]);
  const bufs = [flags | maxPrefix];
  value -= maxPrefix;
  while (value >= 128) {
    bufs.push((value & 0x7f) | 0x80);
    value >>= 7;
  }
  bufs.push(value);
  return Buffer.from(bufs);
}

function encodeString(str) {
  const raw = Buffer.isBuffer(str) ? str : Buffer.from(str, 'ascii');
  const huffLen = huffmanEncodedLength(raw);
  if (huffLen < raw.length) {
    const encoded = huffmanEncode(raw);
    const lenBuf = encodeInteger(encoded.length, 7, 0x80); // H=1
    return Buffer.concat([lenBuf, encoded]);
  }
  const lenBuf = encodeInteger(raw.length, 7, 0x00); // H=0
  return Buffer.concat([lenBuf, raw]);
}

function decodeInteger(data, offset, prefixBits) {
  const maxPrefix = (1 << prefixBits) - 1;
  let value = data[offset] & maxPrefix;
  offset++;
  if (value < maxPrefix) return { value, newOffset: offset };

  let shift = 0;
  while (offset < data.length) {
    const byte = data[offset++];
    value += (byte & 0x7f) << shift;
    shift += 7;
    if (!(byte & 0x80)) break;
  }
  return { value, newOffset: offset };
}

function decodeString(data, offset) {
  const huffmanEncoded = !!(data[offset] & 0x80);
  const { value: length, newOffset: o1 } = decodeInteger(data, offset, 7);
  offset = o1;
  const raw = data.subarray(offset, offset + length);
  offset += length;

  if (huffmanEncoded) return { str: huffmanDecode(raw).toString('ascii'), newOffset: offset };
  return { str: raw.toString('ascii'), newOffset: offset };
}

// ====================================================================
// 5. HPACK ENCODER & DECODER CLASSES
// ====================================================================

const NEVER_INDEX = new Set(['authorization', 'cookie', 'set-cookie', 'proxy-authorization']);

class HpackEncoder {
  constructor(maxTableSize = 4096) {
    this.dynamicTable = new DynamicTable(maxTableSize);
    this._pendingTableSizeUpdate = null;
  }

  setMaxTableSize(size) {
    this._pendingTableSizeUpdate = size;
    this.dynamicTable.setMaxSize(size);
  }

  encode(headers) {
    const bufs = [];
    if (this._pendingTableSizeUpdate !== null) {
      bufs.push(this._encodeTableSizeUpdate(this._pendingTableSizeUpdate));
      this._pendingTableSizeUpdate = null;
    }
    for (const [name, value] of headers) {
      bufs.push(this._encodeHeader(name, value));
    }
    return Buffer.concat(bufs);
  }

  _encodeHeader(name, value) {
    const neverIndex = NEVER_INDEX.has(name);
    const fullKey = `${name}\0${value}`;
    const staticFullIdx = STATIC_FULL_INDEX.get(fullKey);
    
    if (staticFullIdx !== undefined) return this._encodeIndexed(staticFullIdx);

    const dynFullIdx = this.dynamicTable.find(name, value);
    if (dynFullIdx >= 0) return this._encodeIndexed(62 + dynFullIdx);

    let nameIndex = 0;
    const staticNameIdx = STATIC_NAME_INDEX.get(name);
    if (staticNameIdx !== undefined) {
      nameIndex = staticNameIdx;
    } else {
      const dynNameIdx = this.dynamicTable.findName(name);
      if (dynNameIdx >= 0) nameIndex = 62 + dynNameIdx;
    }

    if (neverIndex) return this._encodeLiteralNeverIndexed(nameIndex, name, value);

    this.dynamicTable.add(name, value);
    return this._encodeLiteralWithIndexing(nameIndex, name, value);
  }

  _encodeIndexed(index) { return encodeInteger(index, 7, 0x80); }

  _encodeLiteralWithIndexing(nameIndex, name, value) {
    const bufs = [];
    if (nameIndex > 0) bufs.push(encodeInteger(nameIndex, 6, 0x40));
    else { bufs.push(Buffer.from([0x40])); bufs.push(encodeString(name)); }
    bufs.push(encodeString(value));
    return Buffer.concat(bufs);
  }

  _encodeLiteralNeverIndexed(nameIndex, name, value) {
    const bufs = [];
    if (nameIndex > 0) bufs.push(encodeInteger(nameIndex, 4, 0x10));
    else { bufs.push(Buffer.from([0x10])); bufs.push(encodeString(name)); }
    bufs.push(encodeString(value));
    return Buffer.concat(bufs);
  }

  _encodeTableSizeUpdate(maxSize) { return encodeInteger(maxSize, 5, 0x20); }
}


class HpackDecoder {
  constructor(maxTableSize = 4096) {
    this.dynamicTable = new DynamicTable(maxTableSize);
  }

  setMaxTableSize(size) {
    this.dynamicTable.setMaxSize(size);
  }

  decode(data) {
    const headers = [];
    let offset = 0;

    while (offset < data.length) {
      const byte = data[offset];

      if (byte & 0x80) {
        // 7.1 Indexed Header
        const { value: index, newOffset } = decodeInteger(data, offset, 7);
        offset = newOffset;
        const entry = this._getEntry(index);
        if (!entry) throw new Error(`HPACK: invalid index ${index}`);
        headers.push([entry[0], entry[1]]);
      } else if (byte & 0x40) {
        // 7.2.1 Literal with Incremental Indexing
        const { value: nameIndex, newOffset: o1 } = decodeInteger(data, offset, 6);
        offset = o1;
        let name, value;
        if (nameIndex > 0) {
          const entry = this._getEntry(nameIndex);
          if (!entry) throw new Error(`HPACK: invalid name index ${nameIndex}`);
          name = entry[0];
        } else {
          const { str, newOffset: o2 } = decodeString(data, offset);
          name = str; offset = o2;
        }
        const { str: val, newOffset: o3 } = decodeString(data, offset);
        value = val; offset = o3;
        
        this.dynamicTable.add(name, value);
        headers.push([name, value]);
      } else if (byte & 0x20) {
        // 7.3 Dynamic Table Size Update
        const { value: maxSize, newOffset } = decodeInteger(data, offset, 5);
        offset = newOffset;
        this.dynamicTable.setMaxSize(maxSize);
      } else if (byte & 0x10) {
        // 7.2.3 Literal Never Indexed
        const { value: nameIndex, newOffset: o1 } = decodeInteger(data, offset, 4);
        offset = o1;
        let name, value;
        if (nameIndex > 0) {
          const entry = this._getEntry(nameIndex);
          if (!entry) throw new Error(`HPACK: invalid name index ${nameIndex}`);
          name = entry[0];
        } else {
          const { str, newOffset: o2 } = decodeString(data, offset);
          name = str; offset = o2;
        }
        const { str: val, newOffset: o3 } = decodeString(data, offset);
        value = val; offset = o3;
        headers.push([name, value]);
      } else {
        // 7.2.2 Literal without Indexing
        const { value: nameIndex, newOffset: o1 } = decodeInteger(data, offset, 4);
        offset = o1;
        let name, value;
        if (nameIndex > 0) {
          const entry = this._getEntry(nameIndex);
          if (!entry) throw new Error(`HPACK: invalid name index ${nameIndex}`);
          name = entry[0];
        } else {
          const { str, newOffset: o2 } = decodeString(data, offset);
          name = str; offset = o2;
        }
        const { str: val, newOffset: o3 } = decodeString(data, offset);
        value = val; offset = o3;
        headers.push([name, value]);
      }
    }
    return headers;
  }

  _getEntry(index) {
    if (index < 1) return null;
    if (index < STATIC_TABLE.length) return STATIC_TABLE[index];
    return this.dynamicTable.get(index - 62);
  }
}

// ====================================================================
// EXPORTS
// ====================================================================

module.exports = {
  HPACK_STATIC_TABLE: STATIC_TABLE,
  STATIC_NAME_INDEX,
  STATIC_FULL_INDEX,
  HUFFMAN_TABLE,
  huffmanEncode,
  huffmanDecode,
  huffmanEncodedLength,
  HPACK_DYNAMIC_TABLE: DynamicTable,
  HpackEncoder,
  HpackDecoder,
  encodeInteger,
  encodeString,
  decodeInteger,
  decodeString
};