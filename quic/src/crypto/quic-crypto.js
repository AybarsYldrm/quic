'use strict';

const crypto = require('crypto');
const {
  INITIAL_SALT_V1, INITIAL_SALT_V2,
  AEAD_AES_128_GCM, AEAD_KEY_LENGTH, AEAD_IV_LENGTH,
  AEAD_TAG_LENGTH, HP_KEY_LENGTH,
  HP_MASK_LONG, HP_MASK_SHORT,
  QUIC_VERSION_1, QUIC_VERSION_2,
  RETRY_KEY_V1, RETRY_NONCE_V1,
} = require('../constants');

// ----- HKDF (RFC 5869) -----

function hkdfExtract(hash, salt, ikm) {
  return crypto.createHmac(hash, salt).update(ikm).digest();
}

function hkdfExpandLabel(hash, prk, label, context, length) {
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
  return hkdfExpand(hash, prk, hkdfLabel, length);
}

function hkdfExpand(hash, prk, info, length) {
  const hashLen = hash === 'sha256' ? 32 : 48;
  const n = Math.ceil(length / hashLen);
  const output = [];
  let prev = Buffer.alloc(0);

  for (let i = 1; i <= n; i++) {
    const hmac = crypto.createHmac(hash, prk);
    hmac.update(prev);
    hmac.update(info);
    hmac.update(Buffer.from([i]));
    prev = hmac.digest();
    output.push(prev);
  }

  return Buffer.concat(output).subarray(0, length);
}

// ----- Initial Secrets (RFC 9001 Section 5.2) -----

function deriveInitialSecrets(dcid, version) {
  const salt = (version === QUIC_VERSION_2) ? INITIAL_SALT_V2 : INITIAL_SALT_V1;
  const initialSecret = hkdfExtract('sha256', salt, dcid);

  const clientInitialSecret = hkdfExpandLabel(
    'sha256', initialSecret, 'client in', Buffer.alloc(0), 32
  );
  const serverInitialSecret = hkdfExpandLabel(
    'sha256', initialSecret, 'server in', Buffer.alloc(0), 32
  );

  return {
    clientInitialSecret,
    serverInitialSecret,
    // Initial paketleri her zaman aes-128 (16 byte) kullanır
    clientKeys: derivePacketKeys('sha256', clientInitialSecret, 16),
    serverKeys: derivePacketKeys('sha256', serverInitialSecret, 16),
  };
}

// =======================================================
// YENİ EKLENDİ: 0-RTT (EARLY DATA) KEY DERIVATION (RFC 8446/9001)
// =======================================================
function deriveEarlySecrets(hashAlgo, psk, clientHelloHash) {
  const hashLen = hashAlgo === 'sha384' ? 48 : 32;
  const salt = Buffer.alloc(hashLen); // 0-RTT için salt her zaman sıfırlardan oluşur
  
  // 1. Early Secret: HKDF-Extract(salt = 0, IKM = PSK)
  const earlySecret = hkdfExtract(hashAlgo, salt, psk);
  
  // 2. Client Early Traffic Secret (İstemci 0-RTT verilerini bu anahtarla şifreler)
  const clientEarlyTrafficSecret = hkdfExpandLabel(
    hashAlgo, 
    earlySecret, 
    'c e traffic', 
    clientHelloHash, 
    hashLen
  );
  
  // 3. Paket Şifrelerini (Key, IV, HP) Çıkart (16 byte AES veya 32 byte ChaCha/AES256 için)
  // Not: Chrome 0-RTT'yi genelde hangi Cipher ile anlaştıysa o boyutta yapar.
  // Varsayılan AES-128 kabul edip 16 yolluyoruz; tls-engine veya quic bunu override edebilir.
  const keyLen = 16; 
  return derivePacketKeys(hashAlgo, clientEarlyTrafficSecret, keyLen);
}

// DİNAMİK KEY LENGTH EKLENDİ (ChaCha20 ve AES-256 için 32 byte gereklidir)
function derivePacketKeys(hash, secret, keyLen = 16) {
  const key = hkdfExpandLabel(hash, secret, 'quic key', Buffer.alloc(0), keyLen);
  const iv = hkdfExpandLabel(hash, secret, 'quic iv', Buffer.alloc(0), AEAD_IV_LENGTH); // IV hep 12 byte
  const hp = hkdfExpandLabel(hash, secret, 'quic hp', Buffer.alloc(0), keyLen);
  return { key, iv, hp };
}

// ----- Key Update (RFC 9001 Section 6) -----

function deriveNextSecret(hash, currentSecret) {
  return hkdfExpandLabel(hash, currentSecret, 'quic ku', Buffer.alloc(0),
    hash === 'sha256' ? 32 : 48);
}

// ----- AEAD & Header Protection Native Node.js Sınıfları -----

// Node.js'in yerleşik özellikleri kullanılıyor.
function selectCipher(suite) {
  const id = (suite || 'aes-128-gcm').toLowerCase();

  if (id === 'chacha20-poly1305') {
    return {
      id,
      aeadEncrypt: (key, nonce, aad, pt) => {
        const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
        cipher.setAAD(aad);
        return Buffer.concat([cipher.update(pt), cipher.final(), cipher.getAuthTag()]);
      },
      aeadDecrypt: (key, nonce, aad, ct) => {
        if (ct.length < 16) throw new Error('AEAD: ciphertext too short');
        const encData = ct.subarray(0, ct.length - 16);
        const tag = ct.subarray(ct.length - 16);
        const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
        decipher.setAAD(aad);
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(encData), decipher.final()]);
      },
      hpMask: (hpKey, sample) => {
        // ChaCha20 Header Protection: Node.js chacha20 16-byte IV(sample) bekler
        const cipher = crypto.createCipheriv('chacha20', hpKey, sample);
        return cipher.update(Buffer.alloc(5, 0)); // 5 byte maske üret
      }
    };
  }

  if (id === 'aes-256-gcm') {
    return {
      id,
      aeadEncrypt: (key, nonce, aad, pt) => _aesAeadEncrypt('aes-256-gcm', key, nonce, aad, pt),
      aeadDecrypt: (key, nonce, aad, ct) => _aesAeadDecrypt('aes-256-gcm', key, nonce, aad, ct),
      hpMask: (hpKey, sample) => {
        const c = crypto.createCipheriv('aes-256-ecb', hpKey, null);
        c.setAutoPadding(false);
        return Buffer.concat([c.update(sample), c.final()]);
      }
    };
  }

  // Varsayılan: AES-128-GCM
  return {
    id: 'aes-128-gcm',
    aeadEncrypt: (key, nonce, aad, pt) => _aesAeadEncrypt('aes-128-gcm', key, nonce, aad, pt),
    aeadDecrypt: (key, nonce, aad, ct) => _aesAeadDecrypt('aes-128-gcm', key, nonce, aad, ct),
    hpMask: (hpKey, sample) => {
      const c = crypto.createCipheriv('aes-128-ecb', hpKey, null);
      c.setAutoPadding(false);
      return Buffer.concat([c.update(sample), c.final()]);
    }
  };
}

function _aesAeadEncrypt(algo, key, nonce, aad, pt) {
  const cipher = crypto.createCipheriv(algo, key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  return Buffer.concat([cipher.update(pt), cipher.final(), cipher.getAuthTag()]);
}

function _aesAeadDecrypt(algo, key, nonce, aad, ct) {
  if (ct.length < 16) throw new Error('AEAD: ciphertext too short');
  const encData = ct.subarray(0, ct.length - 16);
  const tag = ct.subarray(ct.length - 16);
  const decipher = crypto.createDecipheriv(algo, key, nonce, { authTagLength: 16 });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encData), decipher.final()]);
}

// ----- Yönlendirici AEAD Fonksiyonları -----

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

// Artık 'algo' parametresi aes-128, aes-256 veya chacha20 string'i olarak geliyor.
function aeadEncrypt(algo, key, nonce, aad, plaintext) {
  return selectCipher(algo).aeadEncrypt(key, nonce, aad, plaintext);
}

function aeadDecrypt(algo, key, nonce, aad, ciphertext) {
  return selectCipher(algo).aeadDecrypt(key, nonce, aad, ciphertext);
}

// ----- Header Protection -----

// 'suite' parametresi codec.js tarafından yollanıyor
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

// Geriye Dönük Uyumluluk
function generateHPMask(hpKey, sample) {
  return selectCipher('aes-128-gcm').hpMask(hpKey, sample);
}

// ----- Retry Integrity Tag (RFC 9001 Section 5.8) -----

function computeRetryIntegrityTag(version, odcid, retryPacketWithoutTag) {
  const pseudoPacket = Buffer.alloc(1 + odcid.length + retryPacketWithoutTag.length);
  pseudoPacket[0] = odcid.length;
  odcid.copy(pseudoPacket, 1);
  retryPacketWithoutTag.copy(pseudoPacket, 1 + odcid.length);

  const cipher = crypto.createCipheriv('aes-128-gcm', RETRY_KEY_V1, RETRY_NONCE_V1,
    { authTagLength: AEAD_TAG_LENGTH });
  cipher.setAAD(pseudoPacket);
  cipher.update(Buffer.alloc(0));
  cipher.final();
  return cipher.getAuthTag();
}

function validateRetryIntegrityTag(version, odcid, retryPacket) {
  if (retryPacket.length < AEAD_TAG_LENGTH) return false;
  const packetBody = retryPacket.subarray(0, retryPacket.length - AEAD_TAG_LENGTH);
  const receivedTag = retryPacket.subarray(retryPacket.length - AEAD_TAG_LENGTH);
  const computedTag = computeRetryIntegrityTag(version, odcid, packetBody);
  return crypto.timingSafeEqual(receivedTag, computedTag);
}

// ----- Connection ID & Token Generation -----

function generateConnectionId(length = 8) {
  return crypto.randomBytes(length);
}

function generateStatelessResetToken() {
  return crypto.randomBytes(16);
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

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-128-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([iv, encrypted, tag]);
}

function validateToken(key, token, clientAddress, clientPort, maxAge) {
  try {
    if (token.length < 12 + 16) return null;

    const iv = token.subarray(0, 12);
    const encrypted = token.subarray(12, token.length - 16);
    const tag = token.subarray(token.length - 16);

    const decipher = crypto.createDecipheriv('aes-128-gcm', key, iv);
    decipher.setAuthTag(tag);
    const payload = Buffer.concat([decipher.update(encrypted), decipher.final()]);

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

// =======================================================
// MODULE EXPORTS
// =======================================================
module.exports = {
  hkdfExtract, hkdfExpandLabel, hkdfExpand,
  deriveInitialSecrets, 
  deriveEarlySecrets, // YENİ EKLENDİ
  derivePacketKeys, deriveNextSecret,
  computeNonce, aeadEncrypt, aeadDecrypt,
  applyHeaderProtection, removeHeaderProtection, generateHPMask,
  selectCipher,
  computeRetryIntegrityTag, validateRetryIntegrityTag,
  generateConnectionId, generateStatelessResetToken,
  generateToken, validateToken,
};