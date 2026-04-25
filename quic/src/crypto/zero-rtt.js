'use strict';

const crypto = require('crypto');
const { hkdfExtract, hkdfExpandLabel, derivePacketKeys } = require('./quic-crypto');
const { ENCRYPTION_LEVEL } = require('../constants');
const { createLogger } = require('../utils/logger'); // ✅ EKLENDİ

const log = createLogger('0-RTT'); // ✅ EKLENDİ

class SessionTicket {
  constructor(options = {}) {
    this.ticket = options.ticket || null;
    this.resumptionSecret = options.resumptionSecret || null;
    this.cipherSuite = options.cipherSuite || 0x1301;
    this.alpn = options.alpn || 'h3';
    this.maxEarlyData = options.maxEarlyData || 0xffffffff;
    this.peerTransportParams = options.peerTransportParams || null;
    this.createdAt = options.createdAt || Date.now();
    this.lifetime = options.lifetime || 7200000;
    this.ageAdd = options.ageAdd || crypto.randomBytes(4).readUInt32BE(0);
    this.serverName = options.serverName || '';
  }

  isValid() {
    return this.ticket !== null &&
           this.resumptionSecret !== null &&
           (Date.now() - this.createdAt) < this.lifetime;
  }

  serialize() {
    return {
      ticket: this.ticket.toString('base64'),
      resumptionSecret: this.resumptionSecret.toString('base64'),
      cipherSuite: this.cipherSuite,
      alpn: this.alpn,
      maxEarlyData: this.maxEarlyData,
      peerTransportParams: this.peerTransportParams
        ? this.peerTransportParams.toString('base64') : null,
      createdAt: this.createdAt,
      lifetime: this.lifetime,
      ageAdd: this.ageAdd,
      serverName: this.serverName,
    };
  }

  static deserialize(data) {
    return new SessionTicket({
      ticket: Buffer.from(data.ticket, 'base64'),
      resumptionSecret: Buffer.from(data.resumptionSecret, 'base64'),
      cipherSuite: data.cipherSuite,
      alpn: data.alpn,
      maxEarlyData: data.maxEarlyData,
      peerTransportParams: data.peerTransportParams
        ? Buffer.from(data.peerTransportParams, 'base64') : null,
      createdAt: data.createdAt,
      lifetime: data.lifetime,
      ageAdd: data.ageAdd,
      serverName: data.serverName,
    });
  }
}

/**
 * ✅ DÜZELTİLDİ: keyLen parametresi eklendi (ChaCha20=32, AES-128=16, AES-256=32)
 */
function deriveZeroRTTKeys(hashAlgo, psk, clientHelloHash, keyLen = 16) {
  const hashLen = hashAlgo === 'sha384' ? 48 : 32;

  const earlySecret = hkdfExtract(hashAlgo, Buffer.alloc(hashLen), psk);

  const clientEarlySecret = hkdfExpandLabel(
    hashAlgo, earlySecret, 'c e traffic', clientHelloHash, hashLen
  );

  // ✅ keyLen artık parametre olarak geliyor — ChaCha20 ve AES-256 için 32
  const keys = derivePacketKeys(hashAlgo, clientEarlySecret, keyLen);

  return {
    earlySecret,
    clientEarlySecret,
    keys,
  };
}

function deriveResumptionSecret(hashAlgo, masterSecret, transcriptHash) {
  const hashLen = hashAlgo === 'sha384' ? 48 : 32;
  return hkdfExpandLabel(
    hashAlgo, masterSecret, 'res master', transcriptHash, hashLen
  );
}

function derivePSK(hashAlgo, ticketKey, encryptedTicket) {
  log.trace('[0-RTT] Verifying ticket with key', ticketKey.toString('hex').slice(0, 8) + '…');
  try {
    if (encryptedTicket.length < 28) {
      log.warn('[0-RTT] Bilet çok kısa, geçersiz.');
      return null;
    }

    const iv  = encryptedTicket.subarray(0, 12);
    const tag = encryptedTicket.subarray(12, 28);
    const ct  = encryptedTicket.subarray(28);

    const decipher = crypto.createDecipheriv('aes-128-gcm', ticketKey, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(ct), decipher.final()]);

    const psk  = decrypted.subarray(0, 32);
    const meta = JSON.parse(decrypted.subarray(32).toString('utf8'));

    log.debug(`[0-RTT] Bilet çözüldü. SNI: ${meta.sni}, Suite: ${meta.suite}`);

    // ✅ meta'yı da döndürüyoruz — suite (0x1303 vb.) keyLen için gerekli
    return { psk, meta };
  } catch (e) {
    log.warn('[0-RTT] Bilet çözme hatası:', e.message);
    return null;
  }
}

function buildNewSessionTicket(options) {
  const {
    lifetime = 7200,
    ageAdd,
    ticketNonce,
    ticket,
    maxEarlyData = 0xffffffff,
  } = options;

  const nonceLen = ticketNonce ? ticketNonce.length : 0;

  const earlyDataExt = Buffer.alloc(8);
  earlyDataExt.writeUInt16BE(0x002a, 0);
  earlyDataExt.writeUInt16BE(4, 2);
  earlyDataExt.writeUInt32BE(maxEarlyData, 4);

  const extLen = earlyDataExt.length;
  const bodyLen = 4 + 4 + 1 + nonceLen + 2 + ticket.length + 2 + extLen;
  const body = Buffer.alloc(bodyLen);
  let off = 0;

  body.writeUInt32BE(lifetime, off); off += 4;
  body.writeUInt32BE(ageAdd, off); off += 4;
  body[off++] = nonceLen;
  if (ticketNonce) { ticketNonce.copy(body, off); off += nonceLen; }
  body.writeUInt16BE(ticket.length, off); off += 2;
  ticket.copy(body, off); off += ticket.length;
  body.writeUInt16BE(extLen, off); off += 2;
  earlyDataExt.copy(body, off);

  const msg = Buffer.alloc(4 + body.length);
  msg[0] = 4;
  msg.writeUIntBE(body.length, 1, 3);
  body.copy(msg, 4);

  return msg;
}

function parseNewSessionTicket(data) {
  let off = 0;

  const lifetime = data.readUInt32BE(off); off += 4;
  const ageAdd   = data.readUInt32BE(off); off += 4;

  const nonceLen   = data[off++];
  const ticketNonce = data.subarray(off, off + nonceLen); off += nonceLen;

  const ticketLen = data.readUInt16BE(off); off += 2;
  const ticket    = data.subarray(off, off + ticketLen); off += ticketLen;

  let maxEarlyData = 0;

  if (off + 2 <= data.length) {
    const extLen = data.readUInt16BE(off); off += 2;
    const extEnd = off + extLen;
    while (off + 4 <= extEnd) {
      const extType    = data.readUInt16BE(off); off += 2;
      const extDataLen = data.readUInt16BE(off); off += 2;
      if (extType === 0x002a && extDataLen >= 4) {
        maxEarlyData = data.readUInt32BE(off);
      }
      off += extDataLen;
    }
  }

  return {
    lifetime: lifetime * 1000,
    ageAdd,
    ticketNonce: Buffer.from(ticketNonce),
    ticket: Buffer.from(ticket),
    maxEarlyData,
  };
}

class SessionTicketStore {
  constructor() {
    this.tickets = new Map();
  }

  store(serverName, ticket) {
    this.tickets.set(serverName, ticket);
  }

  retrieve(serverName) {
    const ticket = this.tickets.get(serverName);
    if (ticket && ticket.isValid()) return ticket;
    if (ticket) this.tickets.delete(serverName);
    return null;
  }

  remove(serverName) {
    this.tickets.delete(serverName);
  }

  clear() {
    this.tickets.clear();
  }
}

module.exports = {
  SessionTicket,
  SessionTicketStore,
  deriveZeroRTTKeys,
  deriveResumptionSecret,
  derivePSK,
  buildNewSessionTicket,
  parseNewSessionTicket,
};