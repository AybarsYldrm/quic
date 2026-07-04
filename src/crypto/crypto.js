'use strict';

// Standart node:crypto yerine kendi yazdığımız saf PKI ve Kripto motorunu dahil ediyoruz.
const {
  hmac,
  sha256,
  sha384,
  randomBytes,
  gcmEncrypt,
  gcmDecrypt,
  aesEncryptBlock,
  aesExpandKey,_bufToBigInt
} = require('@fitfak/ssl');

// ChaCha20-Poly1305 is a symmetric cipher already supported natively by
// Node's OpenSSL binding (unlike the post-quantum KEM/signature schemes this
// project has to hand-roll), so we borrow it here rather than reimplement a
// stream cipher + MAC from scratch.
const nodeCrypto = require('node:crypto');

const {
  INITIAL_SALT_V1, INITIAL_SALT_V2,
  AEAD_AES_128_GCM, AEAD_KEY_LENGTH, AEAD_IV_LENGTH,
  AEAD_TAG_LENGTH, HP_KEY_LENGTH,
  HP_MASK_LONG, HP_MASK_SHORT,
  QUIC_VERSION_1, QUIC_VERSION_2,
  RETRY_KEY_V1, RETRY_NONCE_V1,
} = require('../constants');

// Zamanlama saldırılarına (Timing Attacks) karşı yerel eşitlik kontrolü
function timingSafeEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) {
    out |= a[i] ^ b[i];
  }
  return out === 0;
}

// ----- HKDF (RFC 5869) - Saf Kripto Motoru ile -----

function hkdfExtract(hashAlgo, salt, ikm) {
  const actualSalt = salt && salt.length > 0 ? salt : Buffer.alloc(hashAlgo === 'sha384' ? 48 : 32);
  return hmac(hashAlgo, actualSalt, ikm);
}

function hkdfExpandLabel(hashAlgo, prk, label, context, length) {
  const fullLabel = Buffer.from('tls13 ' + label, 'ascii');
  const hkdfLabel = Buffer.alloc(2 + 1 + fullLabel.length + 1 + context.length);
  let off = 0;
  hkdfLabel.writeUInt16BE(length, off); off += 2;
  hkdfLabel[off++] = fullLabel.length;
  fullLabel.copy(hkdfLabel, off); off += fullLabel.length;
  hkdfLabel[off++] = context.length;
  if (context.length > 0) {
    context.copy(hkdfLabel, off);
  }
  return hkdfExpand(hashAlgo, prk, hkdfLabel, length);
}

function hkdfExpand(hashAlgo, prk, info, length) {
  const hashLen = hashAlgo === 'sha384' ? 48 : 32;
  const n = Math.ceil(length / hashLen);
  const output = [];
  let prev = Buffer.alloc(0);

  for (let i = 1; i <= n; i++) {
    const data = Buffer.concat([prev, info, Buffer.from([i])]);
    prev = hmac(hashAlgo, prk, data);
    output.push(prev);
  }

  return Buffer.concat(output).subarray(0, length);
}

// =======================================================
// QUIC Initial Secrets (RFC 9001 Section 5.2)
// =======================================================

function deriveInitialSecrets(dcid, version) {
  const salt = (version === QUIC_VERSION_2) ? INITIAL_SALT_V2 : INITIAL_SALT_V1;
  const initialSecret = hkdfExtract('sha256', salt, dcid);

  const clientInitialSecret = hkdfExpandLabel('sha256', initialSecret, 'client in', Buffer.alloc(0), 32);
  const serverInitialSecret = hkdfExpandLabel('sha256', initialSecret, 'server in', Buffer.alloc(0), 32);

  return {
    clientInitialSecret,
    serverInitialSecret,
    clientKeys: derivePacketKeys('sha256', clientInitialSecret, 16),
    serverKeys: derivePacketKeys('sha256', serverInitialSecret, 16),
  };
}

// =======================================================
// TLS 1.3 / QUIC Unified Key Schedule (RFC 8446)
// =======================================================

function deriveEarlySecrets(hashAlgo, psk, clientHelloHash) {
  const hashLen = hashAlgo === 'sha384' ? 48 : 32;
  const salt = Buffer.alloc(hashLen); 
  
  const earlySecret = hkdfExtract(hashAlgo, salt, psk);
  const clientEarlyTrafficSecret = hkdfExpandLabel(hashAlgo, earlySecret, 'c e traffic', clientHelloHash, hashLen);
  
  const keyLen = hashAlgo === 'sha384' ? 32 : 16; 
  return {
    earlySecret,
    clientEarlyTrafficSecret,
    keys: derivePacketKeys(hashAlgo, clientEarlyTrafficSecret, keyLen)
  };
}

function deriveTls13HandshakeSecrets(hashAlgo, sharedSecret, earlySecret, handshakeHash) {
  const hashLen = hashAlgo === 'sha384' ? 48 : 32;
  const emptyHash = hashAlgo === 'sha384' ? sha384(Buffer.alloc(0)) : sha256(Buffer.alloc(0));
  
  const derivedEarlySecret = hkdfExpandLabel(hashAlgo, earlySecret, 'derived', emptyHash, hashLen);
  const handshakeSecret = hkdfExtract(hashAlgo, derivedEarlySecret, sharedSecret);
  
  const clientHandshakeTrafficSecret = hkdfExpandLabel(hashAlgo, handshakeSecret, 'c hs traffic', handshakeHash, hashLen);
  const serverHandshakeTrafficSecret = hkdfExpandLabel(hashAlgo, handshakeSecret, 's hs traffic', handshakeHash, hashLen);

  return {
    handshakeSecret,
    clientHandshakeTrafficSecret,
    serverHandshakeTrafficSecret,
    clientKeys: derivePacketKeys(hashAlgo, clientHandshakeTrafficSecret, hashLen === 48 ? 32 : 16),
    serverKeys: derivePacketKeys(hashAlgo, serverHandshakeTrafficSecret, hashLen === 48 ? 32 : 16)
  };
}

function deriveTls13MasterSecrets(hashAlgo, handshakeSecret, transcriptHash) {
  const hashLen = hashAlgo === 'sha384' ? 48 : 32;
  const emptyHash = hashAlgo === 'sha384' ? sha384(Buffer.alloc(0)) : sha256(Buffer.alloc(0));
  
  const derivedHandshakeSecret = hkdfExpandLabel(hashAlgo, handshakeSecret, 'derived', emptyHash, hashLen);
  const masterSecret = hkdfExtract(hashAlgo, derivedHandshakeSecret, Buffer.alloc(hashLen, 0));
  
  const clientAppTrafficSecret = hkdfExpandLabel(hashAlgo, masterSecret, 'c ap traffic', transcriptHash, hashLen);
  const serverAppTrafficSecret = hkdfExpandLabel(hashAlgo, masterSecret, 's ap traffic', transcriptHash, hashLen);

  return {
    masterSecret,
    clientAppTrafficSecret,
    serverAppTrafficSecret,
    clientKeys: derivePacketKeys(hashAlgo, clientAppTrafficSecret, hashLen === 48 ? 32 : 16),
    serverKeys: derivePacketKeys(hashAlgo, serverAppTrafficSecret, hashLen === 48 ? 32 : 16)
  };
}

function derivePacketKeys(hash, secret, keyLen = 16) {
  const key = hkdfExpandLabel(hash, secret, 'quic key', Buffer.alloc(0), keyLen);
  const iv = hkdfExpandLabel(hash, secret, 'quic iv', Buffer.alloc(0), AEAD_IV_LENGTH); 
  const hp = hkdfExpandLabel(hash, secret, 'quic hp', Buffer.alloc(0), keyLen);
  return { key, iv, hp };
}

function deriveNextSecret(hash, currentSecret) {
  return hkdfExpandLabel(hash, currentSecret, 'quic ku', Buffer.alloc(0), hash === 'sha256' ? 32 : 48);
}

// =======================================================
// AEAD & Header Protection (Native Zero-Dependency)
// =======================================================

function normalizeEncrypt(encFunc, key, nonce, aad, pt) {
  const res = encFunc(key, nonce, pt, aad); // Parametre sırası: (key, iv, pt, aad)
  if (res && res.ciphertext !== undefined && res.tag !== undefined) {
    return Buffer.concat([res.ciphertext, res.tag]);
  }
  return res;
}

function normalizeDecrypt(decFunc, key, nonce, aad, combinedCt) {
  if (!combinedCt || combinedCt.length < 16) throw new Error('Ciphertext too short');
  const ct = combinedCt.subarray(0, combinedCt.length - 16);
  const tag = combinedCt.subarray(combinedCt.length - 16);
  return decFunc(key, nonce, ct, aad, tag); // Parametre sırası: (key, iv, ct, aad, tag)
}

function selectCipher(suite) {
  const id = (suite || 'aes-128-gcm').toLowerCase();

  if (id === 'chacha20-poly1305') {
    // Bug fixed here: this previously called global.chacha20Poly1305Encrypt /
    // global.chacha20Poly1305Decrypt / global.chacha20Encrypt, none of which
    // were ever defined anywhere in the codebase. Since ChaCha20-Poly1305 is
    // the FIRST (most preferred) entry in the default cipher suite list,
    // every connection that didn't explicitly restrict ciphers to AES would
    // negotiate it - then silently fail (TypeError swallowed by a bare
    // try/catch in QuicConnection._sendPacket) the moment a Handshake- or
    // 1-RTT-level packet needed to be encrypted with it. This is the reason
    // handshakes seemed to start (the Initial level is hardcoded to
    // AES-128-GCM per RFC 9001 and worked) but never actually completed.
    return {
      id,
      aeadEncrypt: (key, nonce, aad, pt) => {
        const cipher = nodeCrypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: AEAD_TAG_LENGTH });
        cipher.setAAD(aad, { plaintextLength: pt.length });
        const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
        return Buffer.concat([ct, cipher.getAuthTag()]);
      },
      aeadDecrypt: (key, nonce, aad, ct) => {
        if (!ct || ct.length < AEAD_TAG_LENGTH) throw new Error('Ciphertext too short');
        const tag  = ct.subarray(ct.length - AEAD_TAG_LENGTH);
        const body = ct.subarray(0, ct.length - AEAD_TAG_LENGTH);
        const decipher = nodeCrypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: AEAD_TAG_LENGTH });
        decipher.setAAD(aad, { plaintextLength: body.length });
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(body), decipher.final()]);
      },
      // RFC 9001 §5.4.4: sample is 16 bytes = 4-byte little-endian counter
      // followed by a 12-byte nonce, which is exactly Node's `chacha20` IV
      // layout - so the 16-byte sample can be used directly as the IV.
      hpMask: (hpKey, sample) => nodeCrypto.createCipheriv('chacha20', hpKey, sample).update(Buffer.alloc(5, 0)),
    };
  }

  // AES-128-GCM veya AES-256-GCM
  return {
    id,
    aeadEncrypt: (key, nonce, aad, pt) => normalizeEncrypt(gcmEncrypt, key, nonce, aad, pt),
    aeadDecrypt: (key, nonce, aad, ct) => normalizeDecrypt(gcmDecrypt, key, nonce, aad, ct),
    hpMask: (hpKey, sample) => {
      // DÜZELTME: Senin AES motoruna ait blok şifreleme mantığı!
      const ks = aesExpandKey(hpKey);
      return aesEncryptBlock(sample, ks);
    }
  };
}

function computeNonce(iv, packetNumber) {
  const nonce = Buffer.from(iv);
  const pnBuf = Buffer.alloc(AEAD_IV_LENGTH);
  if (typeof packetNumber === 'bigint') {
    pnBuf.writeBigUInt64BE(packetNumber, AEAD_IV_LENGTH - 8);
  } else {
    const hi = Math.floor(packetNumber / 0x100000000);
    const lo = packetNumber >>> 0;
    pnBuf.writeUInt32BE(hi, AEAD_IV_LENGTH - 8);
    pnBuf.writeUInt32BE(lo, AEAD_IV_LENGTH - 4);
  }
  for (let i = 0; i < AEAD_IV_LENGTH; i++) {
    nonce[i] ^= pnBuf[i];
  }
  return nonce;
}

function aeadEncrypt(algo, key, nonce, aad, plaintext) {
  return selectCipher(algo).aeadEncrypt(key, nonce, aad, plaintext);
}

function aeadDecrypt(algo, key, nonce, aad, ciphertext) {
  return selectCipher(algo).aeadDecrypt(key, nonce, aad, ciphertext);
}

// ----- Header Protection -----

function applyHeaderProtection(hp, header, pnOffset, pnLength, isLongHeader, suite = 'aes-128-gcm') {
  const sampleOffset = pnOffset + 4;
  const sample = header.subarray(sampleOffset, sampleOffset + 16);

  if (sample.length < 16) throw new Error('HP: insufficient sample');

  const mask = selectCipher(suite).hpMask(hp, sample);
  const result = Buffer.from(header);

  if (isLongHeader) {
    result[0] ^= (mask[0] & HP_MASK_LONG);
  } else {
    result[0] ^= (mask[0] & HP_MASK_SHORT);
  }

  for (let i = 0; i < pnLength; i++) {
    result[pnOffset + i] ^= mask[1 + i];
  }

  return result;
}

function removeHeaderProtection(hp, packet, pnOffset, isLongHeader, suite = 'aes-128-gcm') {
  const sampleOffset = pnOffset + 4;
  if (sampleOffset + 16 > packet.length) {
    throw new Error('HP remove: packet too short for sample');
  }
  const sample = packet.subarray(sampleOffset, sampleOffset + 16);
  const mask = selectCipher(suite).hpMask(hp, sample);

  const result = Buffer.from(packet);

  if (isLongHeader) {
    result[0] ^= (mask[0] & HP_MASK_LONG);
  } else {
    result[0] ^= (mask[0] & HP_MASK_SHORT);
  }

  const pnLength = (result[0] & 0x03) + 1;

  for (let i = 0; i < pnLength; i++) {
    result[pnOffset + i] ^= mask[1 + i];
  }

  return { packet: result, pnLength };
}

function generateHPMask(hpKey, sample) {
  return selectCipher('aes-128-gcm').hpMask(hpKey, sample);
}

// =======================================================
// Retry Integrity, Connection IDs ve Token Yönetimi
// =======================================================

function computeRetryIntegrityTag(version, odcid, retryPacketWithoutTag) {
  const pseudoPacket = Buffer.alloc(1 + odcid.length + retryPacketWithoutTag.length);
  pseudoPacket[0] = odcid.length;
  odcid.copy(pseudoPacket, 1);
  retryPacketWithoutTag.copy(pseudoPacket, 1 + odcid.length);

  const res = gcmEncrypt(RETRY_KEY_V1, RETRY_NONCE_V1, pseudoPacket, Buffer.alloc(0));
  const combined = (res && res.ciphertext && res.tag) ? Buffer.concat([res.ciphertext, res.tag]) : res;
  return combined.subarray(combined.length - 16);
}

function validateRetryIntegrityTag(version, odcid, retryPacket) {
  if (retryPacket.length < AEAD_TAG_LENGTH) return false;
  const packetBody = retryPacket.subarray(0, retryPacket.length - AEAD_TAG_LENGTH);
  const receivedTag = retryPacket.subarray(retryPacket.length - AEAD_TAG_LENGTH);
  const computedTag = computeRetryIntegrityTag(version, odcid, packetBody);
  return timingSafeEqual(receivedTag, computedTag);
}

function generateConnectionId(length = 8) {
  return randomBytes(length);
}

function generateStatelessResetToken() {
  return randomBytes(16);
}

function generateToken(key, originalDcid, clientAddress, clientPort) {
  const timestamp = Buffer.alloc(8);
  timestamp.writeBigUInt64BE(BigInt(Date.now()));

  const payload = Buffer.concat([
    timestamp,
    Buffer.from([originalDcid.length]),
    originalDcid,
    Buffer.from(clientAddress, 'utf8'),
    Buffer.from(':' + clientPort, 'utf8'),
  ]);

  const iv = randomBytes(12);
  const res = gcmEncrypt(key, iv, payload, Buffer.alloc(0));
  const combined = (res && res.ciphertext && res.tag) ? Buffer.concat([res.ciphertext, res.tag]) : res;

  return Buffer.concat([iv, combined]);
}

function validateToken(key, token, clientAddress, clientPort, maxAge) {
  try {
    if (token.length < 12 + 16) return null;

    const iv = token.subarray(0, 12);
    const ctWithTag = token.subarray(12);
    
    const ct = ctWithTag.subarray(0, ctWithTag.length - 16);
    const tag = ctWithTag.subarray(ctWithTag.length - 16);

    const payload = gcmDecrypt(key, iv, ct, Buffer.alloc(0), tag);
    if (!payload) return null;

    const timestamp = Number(payload.readBigUInt64BE(0));
    if (Date.now() - timestamp > maxAge) return null;

    const dcidLen = payload[8];
    const originalDcid = payload.subarray(9, 9 + dcidLen);
    const addrStr = payload.subarray(9 + dcidLen).toString('utf8');
    const expectedAddr = clientAddress + ':' + clientPort;

    if (addrStr !== expectedAddr) return null;

    return { originalDcid, timestamp };
  } catch (e) {
    return null;
  }
}

module.exports = {
  hkdfExtract, hkdfExpandLabel, hkdfExpand,
  deriveInitialSecrets, deriveEarlySecrets,
  deriveTls13HandshakeSecrets, deriveTls13MasterSecrets,
  derivePacketKeys, deriveNextSecret,
  computeNonce, aeadEncrypt, aeadDecrypt,
  applyHeaderProtection, removeHeaderProtection, generateHPMask,
  selectCipher,
  computeRetryIntegrityTag, validateRetryIntegrityTag,
  generateConnectionId, generateStatelessResetToken,
  generateToken, validateToken,
};