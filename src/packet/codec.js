'use strict';

const {
  PACKET_TYPE, QUIC_VERSION_1, MIN_INITIAL_PACKET_SIZE,
  AEAD_TAG_LENGTH, ENCRYPTION_LEVEL,
} = require('../constants');
const { decodeVarInt, encodeVarInt, varIntLength } = require('../transport/varint');
const {
  computeNonce, aeadEncrypt, aeadDecrypt,
  applyHeaderProtection, removeHeaderProtection,
} = require('../crypto/crypto');

// ═══════════════════════════════════════════════════════════════════════════════
// 1. HTTP/2 (RFC 7540) FRAME CODEC & CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const FrameType = {
  DATA: 0x00, HEADERS: 0x01, PRIORITY: 0x02, RST_STREAM: 0x03, SETTINGS: 0x04,
  PUSH_PROMISE: 0x05, PING: 0x06, GOAWAY: 0x07, WINDOW_UPDATE: 0x08, CONTINUATION: 0x09
};

const FrameFlags = {
  NONE: 0x00, ACK: 0x01, END_STREAM: 0x01, END_HEADERS: 0x04, PADDED: 0x08, PRIORITY: 0x20
};

const SettingsId = {
  HEADER_TABLE_SIZE: 1, ENABLE_PUSH: 2, MAX_CONCURRENT_STREAMS: 3,
  INITIAL_WINDOW_SIZE: 4, MAX_FRAME_SIZE: 5, MAX_HEADER_LIST_SIZE: 6
};

const ErrorCode = {
  NO_ERROR: 0, PROTOCOL_ERROR: 1, INTERNAL_ERROR: 2, FLOW_CONTROL_ERROR: 3,
  SETTINGS_TIMEOUT: 4, STREAM_CLOSED: 5, FRAME_SIZE_ERROR: 6, REFUSED_STREAM: 7,
  CANCEL: 8, COMPRESSION_ERROR: 9, CONNECT_ERROR: 10, ENHANCE_YOUR_CALM: 11,
  INADEQUATE_SECURITY: 12, HTTP_1_1_REQUIRED: 13
};

const DEFAULT_SETTINGS = {
  [SettingsId.HEADER_TABLE_SIZE]: 4096,
  [SettingsId.ENABLE_PUSH]: 1,
  [SettingsId.MAX_CONCURRENT_STREAMS]: 100,
  [SettingsId.INITIAL_WINDOW_SIZE]: 65535,
  [SettingsId.MAX_FRAME_SIZE]: 16384,
  [SettingsId.MAX_HEADER_LIST_SIZE]: 65536
};

function parseFrame(buf, offset = 0) {
  if (buf.length - offset < 9) return null; // Incomplete HTTP/2 frame header
  const length = (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2];
  if (buf.length - offset < 9 + length) return null; // Incomplete payload
  
  const type = buf[offset + 3];
  const flags = buf[offset + 4];
  const streamId = buf.readUInt32BE(offset + 5) & 0x7fffffff;
  const payload = buf.subarray(offset + 9, offset + 9 + length);
  
  return { consumed: 9 + length, frame: { type, flags, streamId, payload } };
}

function serializeFrame(type, flags, streamId, payload) {
  const len = payload ? payload.length : 0;
  const buf = Buffer.alloc(9 + len);
  buf.writeUIntBE(len, 0, 3); // 24-bit length
  buf[3] = type;
  buf[4] = flags;
  buf.writeUInt32BE(streamId & 0x7fffffff, 5);
  if (payload && len > 0) payload.copy(buf, 9);
  return buf;
}

function buildSettingsFrame(settings = {}, isAck = false) {
  if (isAck) return serializeFrame(FrameType.SETTINGS, FrameFlags.ACK, 0, Buffer.alloc(0));
  const entries = Object.entries(settings);
  const payload = Buffer.alloc(entries.length * 6);
  let offset = 0;
  for (const [id, val] of entries) {
    payload.writeUInt16BE(Number(id), offset);
    payload.writeUInt32BE(Number(val), offset + 2);
    offset += 6;
  }
  return serializeFrame(FrameType.SETTINGS, 0, 0, payload);
}

function parseSettingsPayload(payload) {
  const settings = {};
  let offset = 0;
  while (offset + 6 <= payload.length) {
    const id = payload.readUInt16BE(offset);
    const val = payload.readUInt32BE(offset + 2);
    settings[id] = val;
    offset += 6;
  }
  return settings;
}

function buildHeadersFrame(streamId, payload, endStream = false, endHeaders = true) {
  let flags = 0;
  if (endStream) flags |= FrameFlags.END_STREAM;
  if (endHeaders) flags |= FrameFlags.END_HEADERS;
  return serializeFrame(FrameType.HEADERS, flags, streamId, payload);
}

function buildDataFrame(streamId, payload, endStream = false) {
  let flags = 0;
  if (endStream) flags |= FrameFlags.END_STREAM;
  return serializeFrame(FrameType.DATA, flags, streamId, payload);
}

function buildWindowUpdateFrame(streamId, increment) {
  const payload = Buffer.alloc(4);
  payload.writeUInt32BE(increment & 0x7fffffff, 0);
  return serializeFrame(FrameType.WINDOW_UPDATE, 0, streamId, payload);
}

function buildRstStreamFrame(streamId, errorCode) {
  const payload = Buffer.alloc(4);
  payload.writeUInt32BE(errorCode, 0);
  return serializeFrame(FrameType.RST_STREAM, 0, streamId, payload);
}

function buildGoawayFrame(lastStreamId, errorCode, debugData = '') {
  const debugBuf = Buffer.from(debugData);
  const payload = Buffer.alloc(8 + debugBuf.length);
  payload.writeUInt32BE(lastStreamId & 0x7fffffff, 0);
  payload.writeUInt32BE(errorCode, 4);
  debugBuf.copy(payload, 8);
  return serializeFrame(FrameType.GOAWAY, 0, 0, payload);
}

function buildPingFrame(opaqueData, isAck = false) {
  let data = opaqueData || Buffer.alloc(8, 0);
  if (data.length !== 8) {
    const old = data;
    data = Buffer.alloc(8, 0);
    old.copy(data);
  }
  return serializeFrame(FrameType.PING, isAck ? FrameFlags.ACK : 0, 0, data);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. QUIC PACKET PARSING & DECRYPTION (Original Code)
// ═══════════════════════════════════════════════════════════════════════════════

function parsePacketHeader(buf) {
  if (buf.length < 1) throw new Error('Packet too short');
  const firstByte = buf[0];
  const isLong = (firstByte & 0x80) !== 0;
  return isLong ? parseLongHeader(buf) : parseShortHeader(buf);
}

function parseLongHeader(buf) {
  if (buf.length < 7) throw new Error('Long header too short');

  let offset = 0;
  const firstByte = buf[offset++];

  if ((firstByte & 0x40) === 0) {
    throw new Error('Fixed bit not set in long header');
  }

  const packetType = (firstByte & 0x30) >> 4;
  const version = buf.readUInt32BE(offset); offset += 4;

  if (version === 0) return parseVersionNegotiation(buf, offset);

  const dcidLen = buf[offset++];
  if (offset + dcidLen > buf.length) throw new Error('DCID overflows');
  const dcid = buf.subarray(offset, offset + dcidLen); offset += dcidLen;

  const scidLen = buf[offset++];
  if (offset + scidLen > buf.length) throw new Error('SCID overflows');
  const scid = buf.subarray(offset, offset + scidLen); offset += scidLen;

  if (packetType === PACKET_TYPE.RETRY) {
    if (buf.length - offset < 16) throw new Error('Retry too short for integrity tag');
    const retryToken = buf.subarray(offset, buf.length - 16);
    const integrityTag = buf.subarray(buf.length - 16);
    return {
      isLong: true,
      packetType,
      version,
      dcid: Buffer.from(dcid),
      scid: Buffer.from(scid),
      retryToken: Buffer.from(retryToken),
      integrityTag: Buffer.from(integrityTag),
      headerLength: offset,
      totalLength: buf.length,
    };
  }

  let token = null;
  if (packetType === PACKET_TYPE.INITIAL) {
    const { value: tokenLen, length: tlLen } = decodeVarInt(buf, offset);
    offset += tlLen;
    token = buf.subarray(offset, offset + tokenLen);
    offset += tokenLen;
  }

  const { value: pktLen, length: plLen } = decodeVarInt(buf, offset);
  offset += plLen;

  return {
    isLong: true,
    packetType,
    version,
    dcid: Buffer.from(dcid),
    scid: Buffer.from(scid),
    token: token ? Buffer.from(token) : null,
    payloadLength: pktLen,
    pnOffset: offset,
    headerLength: offset,
    totalLength: offset + pktLen,
  };
}

function parseShortHeader(buf) {
  const firstByte = buf[0];
  if ((firstByte & 0x40) === 0) {
    throw new Error('Fixed bit not set in short header');
  }
  return {
    isLong: false,
    packetType: null,
    firstByte,
    headerBuffer: buf,
  };
}

function parseVersionNegotiation(buf, offset) {
  const dcidLen = buf[offset++];
  const dcid = buf.subarray(offset, offset + dcidLen); offset += dcidLen;
  const scidLen = buf[offset++];
  const scid = buf.subarray(offset, offset + scidLen); offset += scidLen;

  const versions = [];
  while (offset + 4 <= buf.length) {
    versions.push(buf.readUInt32BE(offset));
    offset += 4;
  }

  return {
    isLong: true,
    packetType: 'VERSION_NEGOTIATION',
    version: 0,
    dcid: Buffer.from(dcid),
    scid: Buffer.from(scid),
    versions,
  };
}

function decryptPacket(packet, header, keys, largestPn) {
  const safeLargestPn = (largestPn === undefined || largestPn === null || largestPn === -1) ? 0 : largestPn;
  const { key, iv, hp, suite = 'aes-128-gcm' } = keys;

  const { packet: unprotected, pnLength } = removeHeaderProtection(
    hp, packet, header.pnOffset, header.isLong, suite
  );

  let truncatedPn = 0;
  for (let i = 0; i < pnLength; i++) {
    truncatedPn = (truncatedPn << 8) | unprotected[header.pnOffset + i];
  }

  const packetNumber = decodePacketNumber(truncatedPn, pnLength, safeLargestPn);

  const aadEnd = header.pnOffset + pnLength;
  const aad = unprotected.subarray(0, aadEnd);

  let payloadEnd;
  if (header.isLong) {
    payloadEnd = header.pnOffset + header.payloadLength;
  } else {
    payloadEnd = packet.length;
  }
  
  const ciphertext = unprotected.subarray(aadEnd, payloadEnd);
  const nonce = computeNonce(iv, packetNumber);
  
  const plaintext = aeadDecrypt(suite, key, nonce, aad, ciphertext);

  return {
    packetNumber,
    plaintext,
    headerLength: aadEnd,
    totalConsumed: payloadEnd,
  };
}

function decodePacketNumber(truncatedPn, pnLength, largestPn) {
  const tpn = BigInt(truncatedPn >>> 0);
  const pnNbits = BigInt(pnLength * 8);
  const pnWin = 1n << pnNbits;
  const pnHalfWin = pnWin >> 1n;
  const pnMask = pnWin - 1n;

  const expectedPn = largestPn === -1 ? 0n : BigInt(largestPn) + 1n;
  const candidatePn = (expectedPn & ~pnMask) | tpn;

  if (candidatePn + pnHalfWin <= expectedPn && candidatePn < (1n << 62n) - pnWin) {
    return Number(candidatePn + pnWin);
  }
  if (candidatePn > expectedPn + pnHalfWin && candidatePn >= pnWin) {
    return Number(candidatePn - pnWin);
  }
  return Number(candidatePn);
}

function ensureMinPayload(payload) {
  if (payload.length >= 4) return payload;
  return Buffer.concat([payload, Buffer.alloc(4 - payload.length, 0)]);
}

function buildLongHeaderPacket(options) {
  const { packetType, version, dcid, scid, token, packetNumber, keys } = options;
  let { payload } = options;
  const suite = keys.suite || 'aes-128-gcm';

  payload = ensureMinPayload(payload);
  const pnLength = packetNumberLength(packetNumber);
  const pnBuf = encodePacketNumber(packetNumber, pnLength);

  let firstByte = 0xc0;
  firstByte |= (packetType << 4);
  firstByte |= (pnLength - 1);

  const headerParts = [];
  headerParts.push(Buffer.from([firstByte]));

  const versionBuf = Buffer.alloc(4);
  versionBuf.writeUInt32BE(version, 0);
  headerParts.push(versionBuf);

  headerParts.push(Buffer.from([dcid.length]));
  headerParts.push(dcid);
  headerParts.push(Buffer.from([scid.length]));
  headerParts.push(scid);

  if (packetType === PACKET_TYPE.INITIAL) {
    const tokenBuf = token || Buffer.alloc(0);
    headerParts.push(encodeVarInt(tokenBuf.length));
    if (tokenBuf.length > 0) headerParts.push(tokenBuf);
  }

  const headerPrefix = Buffer.concat(headerParts);

  if (packetType === PACKET_TYPE.INITIAL) {
    const encPayloadLen = payload.length + AEAD_TAG_LENGTH;
    const pktLen = pnLength + encPayloadLen;
    const pktLenSize = varIntLength(pktLen);
    const totalSize = headerPrefix.length + pktLenSize + pnLength + encPayloadLen;

    if (totalSize < MIN_INITIAL_PACKET_SIZE) {
      const paddingNeeded = MIN_INITIAL_PACKET_SIZE - totalSize;
      payload = Buffer.concat([payload, Buffer.alloc(paddingNeeded, 0)]);
    }
  }

  const encPayloadLen = payload.length + AEAD_TAG_LENGTH;
  const pktLen = pnLength + encPayloadLen;

  const header = Buffer.concat([headerPrefix, encodeVarInt(pktLen), pnBuf]);
  const pnOffset = header.length - pnLength;

  const nonce = computeNonce(keys.iv, packetNumber);
  const ciphertext = aeadEncrypt(suite, keys.key, nonce, header, payload);
  const fullPacket = Buffer.concat([header, ciphertext]);

  return applyHeaderProtection(keys.hp, fullPacket, pnOffset, pnLength, true, suite);
}

function buildShortHeaderPacket(options) {
  const { dcid, packetNumber, keys, keyPhase = 0, spinBit = 0 } = options;
  let { payload } = options;
  const suite = keys.suite || 'aes-128-gcm';

  payload = ensureMinPayload(payload);
  const pnLength = packetNumberLength(packetNumber);
  const pnBuf = encodePacketNumber(packetNumber, pnLength);

  let firstByte = 0x40;
  if (spinBit) firstByte |= 0x20;
  if (keyPhase) firstByte |= 0x04;
  firstByte |= (pnLength - 1);

  const header = Buffer.concat([ Buffer.from([firstByte]), dcid, pnBuf ]);
  const pnOffset = 1 + dcid.length;

  const nonce = computeNonce(keys.iv, packetNumber);
  const ciphertext = aeadEncrypt(suite, keys.key, nonce, header, payload);
  const fullPacket = Buffer.concat([header, ciphertext]);

  return applyHeaderProtection(keys.hp, fullPacket, pnOffset, pnLength, false, suite);
}

function buildVersionNegotiation(dcid, scid, supportedVersions) {
  const parts = [];
  const firstByte = 0x80 | (Math.random() * 0x7f) | 0;
  parts.push(Buffer.from([firstByte]));
  parts.push(Buffer.alloc(4, 0));
  parts.push(Buffer.from([dcid.length]));
  parts.push(dcid);
  parts.push(Buffer.from([scid.length]));
  parts.push(scid);

  for (const v of supportedVersions) {
    const vBuf = Buffer.alloc(4);
    vBuf.writeUInt32BE(v, 0);
    parts.push(vBuf);
  }

  return Buffer.concat(parts);
}

function packetNumberLength(pn) {
  if (pn <= 0xff) return 1;
  if (pn <= 0xffff) return 2;
  if (pn <= 0xffffff) return 3;
  return 4;
}

function encodePacketNumber(pn, length) {
  const buf = Buffer.alloc(length);
  for (let i = length - 1; i >= 0; i--) {
    buf[i] = pn & 0xff;
    pn >>= 8;
  }
  return buf;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. UNIFIED EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = {
  // HTTP/2 Exports
  parseFrame, serializeFrame, buildSettingsFrame, parseSettingsPayload,
  buildHeadersFrame, buildDataFrame, buildWindowUpdateFrame,
  buildRstStreamFrame, buildGoawayFrame, buildPingFrame,
  FrameType, FrameFlags, SettingsId, DEFAULT_SETTINGS, ErrorCode,
  
  // QUIC Exports
  parsePacketHeader, parseLongHeader, parseShortHeader,
  decryptPacket, decodePacketNumber,
  buildLongHeaderPacket, buildShortHeaderPacket, buildVersionNegotiation,
  packetNumberLength, encodePacketNumber,
};