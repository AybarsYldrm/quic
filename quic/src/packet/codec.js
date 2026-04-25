'use strict';

const {
  PACKET_TYPE, QUIC_VERSION_1, MIN_INITIAL_PACKET_SIZE,
  AEAD_TAG_LENGTH, ENCRYPTION_LEVEL,
} = require('../constants');
const { decodeVarInt, encodeVarInt, varIntLength } = require('../transport/varint');
const {
  computeNonce, aeadEncrypt, aeadDecrypt,
  applyHeaderProtection, removeHeaderProtection,
} = require('../crypto/quic-crypto');

// ----- Packet Parsing -----

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

  // RFC 9000 §17.2.5: Retry has no token-length, no packet-number length,
  // no payload length. After SCID the rest of the packet is
  // <retry-token> || <16-byte retry-integrity-tag>.
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

// ----- Packet Decryption -----

// ----- Packet Decryption -----

function decryptPacket(packet, header, keys, largestPn) {
  // 1. Treat undefined / -1 largestPn as 0 to avoid BigInt(undefined) crashes.
  const safeLargestPn = (largestPn === undefined || largestPn === null || largestPn === -1) ? 0 : largestPn;

  // 2. Pull AEAD material out of the keys bundle.
  const { key, iv, hp, suite = 'aes-128-gcm' } = keys;

  // 3. Strip header protection (unmask the first byte and the packet number).
  const { packet: unprotected, pnLength } = removeHeaderProtection(
    hp, packet, header.pnOffset, header.isLong, suite
  );

  // 4. Read the truncated packet number.
  let truncatedPn = 0;
  for (let i = 0; i < pnLength; i++) {
    truncatedPn = (truncatedPn << 8) | unprotected[header.pnOffset + i];
  }

  const packetNumber = decodePacketNumber(truncatedPn, pnLength, safeLargestPn);

  // 5. AEAD decryption.
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
  
  // Dynamic AEAD decryption (suite chosen by the negotiated cipher)
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

// ----- Payload Padding for Header Protection -----

function ensureMinPayload(payload) {
  if (payload.length >= 4) return payload;
  return Buffer.concat([payload, Buffer.alloc(4 - payload.length, 0)]);
}

// ----- Packet Building -----

function buildLongHeaderPacket(options) {
  const {
    packetType, version, dcid, scid, token,
    packetNumber, keys,
  } = options;
  let { payload } = options;

  // Pick the AEAD per cipher-suite (aes-128-gcm, aes-256-gcm, chacha20-poly1305)
  const suite = keys.suite || 'aes-128-gcm';

  // Ensure minimum payload for HP
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
  
  // Dynamic AEAD encryption
  const ciphertext = aeadEncrypt(suite, keys.key, nonce, header, payload);

  const fullPacket = Buffer.concat([header, ciphertext]);

  // Dynamic header protection
  return applyHeaderProtection(keys.hp, fullPacket, pnOffset, pnLength, true, suite);
}

function buildShortHeaderPacket(options) {
  const {
    dcid, packetNumber, keys, keyPhase = 0, spinBit = 0,
  } = options;
  let { payload } = options;

  // Pick the AEAD per cipher-suite (aes-128-gcm, aes-256-gcm, chacha20-poly1305)
  const suite = keys.suite || 'aes-128-gcm';

  payload = ensureMinPayload(payload);

  const pnLength = packetNumberLength(packetNumber);
  const pnBuf = encodePacketNumber(packetNumber, pnLength);

  let firstByte = 0x40;
  if (spinBit) firstByte |= 0x20;
  if (keyPhase) firstByte |= 0x04;
  firstByte |= (pnLength - 1);

  const header = Buffer.concat([
    Buffer.from([firstByte]),
    dcid,
    pnBuf,
  ]);

  const pnOffset = 1 + dcid.length;

  const nonce = computeNonce(keys.iv, packetNumber);
  
  // Dynamic AEAD encryption
  const ciphertext = aeadEncrypt(suite, keys.key, nonce, header, payload);

  const fullPacket = Buffer.concat([header, ciphertext]);

  // Dynamic header protection
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

// ----- Helpers -----

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

module.exports = {
  parsePacketHeader, parseLongHeader, parseShortHeader,
  decryptPacket, decodePacketNumber,
  buildLongHeaderPacket, buildShortHeaderPacket, buildVersionNegotiation,
  packetNumberLength, encodePacketNumber,
};