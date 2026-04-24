'use strict';

/**
 * ChaCha20-Poly1305 Cipher Suite for QUIC - RFC 9001 Section 5.4.3
 *
 * Provides an alternative to AES-128-GCM for environments without
 * AES-NI hardware acceleration. Uses ChaCha20 for header protection
 * instead of AES-ECB.
 */

const crypto = require('crypto');
const { AEAD_IV_LENGTH, AEAD_TAG_LENGTH } = require('../constants');

const CHACHA20_KEY_LENGTH = 32;
const CHACHA20_HP_KEY_LENGTH = 32;

/**
 * ChaCha20-Poly1305 AEAD encryption
 */
function chachaAeadEncrypt(key, nonce, aad, plaintext) {
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, {
    authTagLength: AEAD_TAG_LENGTH,
  });
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([encrypted, tag]);
}

/**
 * ChaCha20-Poly1305 AEAD decryption
 */
function chachaAeadDecrypt(key, nonce, aad, ciphertext) {
  if (ciphertext.length < AEAD_TAG_LENGTH) {
    throw new Error('ChaCha20: ciphertext too short');
  }
  const encData = ciphertext.subarray(0, ciphertext.length - AEAD_TAG_LENGTH);
  const tag = ciphertext.subarray(ciphertext.length - AEAD_TAG_LENGTH);

  const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, {
    authTagLength: AEAD_TAG_LENGTH,
  });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encData), decipher.final()]);
}

/**
 * ChaCha20 header protection mask - RFC 9001 Section 5.4.4
 *
 * Unlike AES-based suites which use AES-ECB, ChaCha20 uses:
 *   counter = sample[0..3] (little-endian)
 *   nonce   = sample[4..15]
 *   mask    = ChaCha20(hp_key, counter, nonce, 0x00000...)
 */
function chachaGenerateHPMask(hpKey, sample) {
  if (sample.length < 16) {
    throw new Error('ChaCha20 HP: insufficient sample');
  }

  // counter = first 4 bytes of sample (little-endian 32-bit)
  const counter = sample.readUInt32LE(0);
  // nonce = bytes 4..15 of sample
  const nonce = sample.subarray(4, 16);

  // Build the IV: 4 bytes counter (LE) + 8 bytes nonce
  // Node.js chacha20 takes a 16-byte IV: counter(4LE) + nonce(12)
  // Actually, chacha20 in Node.js crypto expects 16-byte nonce
  // We use the raw chacha20 stream cipher
  const iv = Buffer.alloc(16);
  iv.writeUInt32LE(counter, 0);
  nonce.copy(iv, 4);

  const cipher = crypto.createCipheriv('chacha20', hpKey, iv);
  // Generate 5 bytes of mask (encrypt 5 zero bytes)
  const mask = cipher.update(Buffer.alloc(5, 0));
  cipher.destroy();

  return mask;
}

/**
 * Derive ChaCha20-Poly1305 packet keys from secret
 */
function deriveChaChaPacketKeys(hash, secret) {
  const { hkdfExpandLabel } = require('./quic-crypto');
  const key = hkdfExpandLabel(hash, secret, 'quic key', Buffer.alloc(0), CHACHA20_KEY_LENGTH);
  const iv = hkdfExpandLabel(hash, secret, 'quic iv', Buffer.alloc(0), AEAD_IV_LENGTH);
  const hp = hkdfExpandLabel(hash, secret, 'quic hp', Buffer.alloc(0), CHACHA20_HP_KEY_LENGTH);
  return { key, iv, hp };
}

/**
 * Cipher suite registry
 */
const CIPHER_SUITES = {
  0x1301: { // TLS_AES_128_GCM_SHA256
    name: 'AES-128-GCM',
    hash: 'sha256',
    hashLen: 32,
    keyLen: 16,
    aead: 'aes-128-gcm',
    hpAlgo: 'aes',
  },
  0x1302: { // TLS_AES_256_GCM_SHA384
    name: 'AES-256-GCM',
    hash: 'sha384',
    hashLen: 48,
    keyLen: 32,
    aead: 'aes-256-gcm',
    hpAlgo: 'aes',
  },
  0x1303: { // TLS_CHACHA20_POLY1305_SHA256
    name: 'ChaCha20-Poly1305',
    hash: 'sha256',
    hashLen: 32,
    keyLen: 32,
    aead: 'chacha20-poly1305',
    hpAlgo: 'chacha20',
  },
};

function getCipherSuite(id) {
  return CIPHER_SUITES[id] || null;
}

module.exports = {
  chachaAeadEncrypt,
  chachaAeadDecrypt,
  chachaGenerateHPMask,
  deriveChaChaPacketKeys,
  getCipherSuite,
  CIPHER_SUITES,
  CHACHA20_KEY_LENGTH,
  CHACHA20_HP_KEY_LENGTH,
};