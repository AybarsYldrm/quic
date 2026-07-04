'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║  UNIFIED TLS 1.3 ENGINE (QUIC + TCP)                             ║
 * ║  Zero-Dependency | Post-Quantum (ML-KEM-768) | Hybrid X25519     ║
 * ╚══════════════════════════════════════════════════════════════════╝
 */

const { EventEmitter } = require('events');
const { createLogger }  = require('../utils/logger');
const { CertificateValidator } = require('./cert-validator');
const { timingSafeEqual } = require('node:crypto');
const { ENCRYPTION_LEVEL } = require('../constants'); 

const { hkdfExtract, hkdfExpandLabel } = require('./crypto');
const { sha256: rawSha256, _bufToBigInt, _bigIntToBuf, modPow,
   pemToEcPriv, pemToRsaPriv, mldsaSign,ecdsaSign ,
   randomBytes, sha256, sha384, hmac,
  generateX25519KeyPair, x25519,
  mlkem768GenerateKeyPair, mlkemEncapsulate, mlkemDecapsulate,
  gcmEncrypt
  } = require('@fitfak/ssl');

const log = createLogger('TLS');

const TLS_VERSION_13 = 0x0304;

const TLS_HANDSHAKE = {
  CLIENT_HELLO:         1,
  SERVER_HELLO:         2,
  NEW_SESSION_TICKET:   4,
  ENCRYPTED_EXTENSIONS: 8,
  CERTIFICATE:          11,
  CERTIFICATE_REQUEST:  13,
  CERTIFICATE_VERIFY:   15,
  FINISHED:             20,
};

// TLS 1.3 Alert Kodları (RFC 8446)
const TLS_ALERTS = {
  UNEXPECTED_MESSAGE:      10,
  BAD_RECORD_MAC:          20,
  HANDSHAKE_FAILURE:       40,
  ILLEGAL_PARAMETER:       47,
  DECODE_ERROR:            50,
  DECRYPT_ERROR:           51,
  PROTOCOL_VERSION:        70,
  INTERNAL_ERROR:          80,
  NO_APPLICATION_PROTOCOL: 120,
};

const GROUP_X25519          = 0x001d;
const GROUP_X25519_MLKEM768 = 0x11EC; 
const PQC_GROUP_ALT         = 0xfe30; 

const SIG_ECDSA_SECP256R1_SHA256 = 0x0403;
const SIG_RSA_PSS_RSAE_SHA256    = 0x0804;
const SIG_ML_DSA_65              = 0x0808; 

const QUIC_TP_EXTENSION = 0x0039;

const SUITE_INFO = {
  0x1301: { name: 'TLS_AES_128_GCM_SHA256',       hash: 'sha256', hashLen: 32, keyLen: 16, aead: 'aes-128-gcm' },
  0x1302: { name: 'TLS_AES_256_GCM_SHA384',       hash: 'sha384', hashLen: 48, keyLen: 32, aead: 'aes-256-gcm' },
  0x1303: { name: 'TLS_CHACHA20_POLY1305_SHA256', hash: 'sha256', hashLen: 32, keyLen: 32, aead: 'chacha20-poly1305' },
};

const CIPHER_ALIASES = {
  'TLS_AES_128_GCM_SHA256': 0x1301, 'AES_128': 0x1301,
  'TLS_AES_256_GCM_SHA384': 0x1302, 'AES_256': 0x1302,
  'TLS_CHACHA20_POLY1305_SHA256': 0x1303, 'CHACHA20': 0x1303,
};

function _wrapHandshake(type, body) {
  const hdr = Buffer.alloc(4);
  hdr[0] = type;
  hdr.writeUIntBE(body.length, 1, 3);
  return Buffer.concat([hdr, body]);
}

function _buildExtension(type, data) {
  const buf = Buffer.alloc(4 + data.length);
  buf.writeUInt16BE(type, 0);
  buf.writeUInt16BE(data.length, 2);
  data.copy(buf, 4);
  return buf;
}

function _mgf1(seed, len) {
  const out = Buffer.alloc(len);
  let written = 0;
  for (let ctr = 0; written < len; ctr++) {
    const ctrBuf = Buffer.alloc(4);
    ctrBuf.writeUInt32BE(ctr, 0);
    const hash = rawSha256(Buffer.concat([seed, ctrBuf]));
    const take = Math.min(32, len - written);
    hash.copy(out, written, 0, take);
    written += take;
  }
  return out;
}

function _rsaSignPss(privKey, data) {
  const mHash  = rawSha256(data);
  const hLen   = 32, sLen = 32;
  const emBits = privKey.n.toString(2).length - 1;
  const emLen  = Math.ceil(emBits / 8);

  const salt   = randomBytes(sLen);
  const H      = rawSha256(Buffer.concat([Buffer.alloc(8, 0), mHash, salt]));
  const PS     = Buffer.alloc(emLen - sLen - hLen - 2, 0);
  const DB     = Buffer.concat([PS, Buffer.from([0x01]), salt]);
  const dbMask = _mgf1(H, DB.length);

  const maskedDB = Buffer.allocUnsafe(DB.length);
  for (let i = 0; i < DB.length; i++) maskedDB[i] = DB[i] ^ dbMask[i];
  maskedDB[0] &= (0xff >> (8 * emLen - emBits));

  const EM = Buffer.concat([maskedDB, H, Buffer.from([0xbc])]);
  const m  = _bufToBigInt(EM);

  let sig;
  if (privKey.p && privKey.q && privKey.dp && privKey.dq && privKey.qInv) {
    const m1 = modPow(m % privKey.p, privKey.dp, privKey.p);
    const m2 = modPow(m % privKey.q, privKey.dq, privKey.q);
    let h = (privKey.qInv * (m1 - m2)) % privKey.p;
    if (h < 0n) h += privKey.p;
    sig = m2 + h * privKey.q;
  } else {
    sig = modPow(m, privKey.d, privKey.n);
  }
  return _bigIntToBuf(sig, Math.ceil(privKey.n.toString(2).length / 8));
}

class TLS extends EventEmitter {
  constructor(options = {}) {
    super();

    this.isServer  = options.isServer || false;
    this.transport = (options.transport || 'quic').toLowerCase(); 
    this.roleLog   = this.isServer ? '[SERVER]' : '[CLIENT]';

    this.cert        = options.cert  || null;
    this.key         = options.key   || null;
    this.mldsaKeys   = options.mldsaKeys || null;

    // DÜZELTME: Tüm olası modern protokolleri kapsayan zırhlı ALPN listesi
    this.alpn       = options.alpn || ['h3', 'h2', 'http/1.1', 'hq-interop'];
    this.serverName = options.serverName || 'localhost';
    this.transportParams = (this.transport === 'quic') ? (options.transportParams || Buffer.alloc(0)) : Buffer.alloc(0);

    this.requestCert        = options.requestCert || false;
    this.rejectUnauthorized = options.rejectUnauthorized !== undefined ? options.rejectUnauthorized : false;
    this.ca                 = options.ca || null;
    this.clientCert         = options.clientCert || null;
    this.clientKey          = options.clientKey || null;
    this._sessionTicket = options.sessionTicket || null;

    const rawCiphers = options.cipherSuites || options.allowedCiphers || ['CHACHA20', 'AES_256', 'AES_128'];
    this.allowedCiphers = rawCiphers.map(c => {
      if (typeof c === 'string') {
        const k = c.toUpperCase();
        if (CIPHER_ALIASES[k]) return CIPHER_ALIASES[k];
        throw new Error(`[TLS_FATAL] Bilinmeyen şifreleme paketi '${c}'`);
      }
      return c;
    });

    this.enable0rtt      = options.enable0rtt !== undefined ? options.enable0rtt : true;
    this.ticketLifetime  = options.ticketLifetime || 172800;
    this.maxEarlyData    = options.maxEarlyData   || 0xffffffff;
    
    this._ticketKey = options.ticketKey
      ? (Buffer.isBuffer(options.ticketKey) ? options.ticketKey : Buffer.from(options.ticketKey, 'hex'))
      : randomBytes(32);

    this.clientAlpns   = [];
    this.clientSigAlgs = []; 
    this.selectedAlpn  = null;
    this.state         = 'INIT';

    this.cipherSuite  = null;
    this.hashAlgo     = null;
    this.hashLen      = null;
    this.keyLen       = null;
    this.pqcPolicy    = options.pqcPolicy || 'preferred';

    if (!this.isServer) {
      this._applyCipherSuite(this.allowedCiphers[0]);
    } else {
      this.hashAlgo = 'sha256';
      this.hashLen  = 32;
    }

    this.x25519Key = generateX25519KeyPair();
    // src/crypto/tls.js içerisinde (200. satır civarı)

    if (!this.isServer) {
      this.mlkemKey = mlkem768GenerateKeyPair();
      
      // HATA BURADAYDI:
      // this.mlkemKey.publicKey yerine this.mlkemKey.ek kullanmalısın
      // Çünkü senin ML-KEM implementation'ın public key'i 'ek' olarak dönüyor.
      
      const mlkemPub = this.mlkemKey ? this.mlkemKey.ek : null; 
      const x25519Pub = this.x25519Key ? (this.x25519Key.publicKeyRaw || this.x25519Key.publicKey) : null;

      if (!mlkemPub || !x25519Pub) {
          throw new Error("Anahtar üretimi başarısız oldu!");
      }

      // Buffer'ı doğru şekilde birleştir
      this.hybridPubKey = Buffer.concat([mlkemPub, x25519Pub]);
    }

    this.negotiatedGroup     = null;
    this._hybridSharedSecret = null;
    this.peerPublicKey       = null;
    this.serverSharePayload  = null;

    this.transcriptMessages = [];
    this.clientRandom       = null;
    this.serverRandom       = null;
    this.clientSessionId    = Buffer.alloc(0);
    
    this.keys = {
      [ENCRYPTION_LEVEL.HANDSHAKE]: null,
      [ENCRYPTION_LEVEL.ONE_RTT]:   null,
    };

    this.cryptoStreams = {
      [ENCRYPTION_LEVEL.INITIAL]:   { received: new Map(), nextExpected: 0, buffer: Buffer.alloc(0) },
      [ENCRYPTION_LEVEL.HANDSHAKE]: { received: new Map(), nextExpected: 0, buffer: Buffer.alloc(0) },
      [ENCRYPTION_LEVEL.ONE_RTT]:   { received: new Map(), nextExpected: 0, buffer: Buffer.alloc(0) },
    };

    this.peerTransportParams = null;
    this.peerIdentity        = null;
    this.peerCertificate     = null;
    this.peerServerName      = null;
    this.peerAttempted0RTT   = false;

    this.onHandshakeData = null; 
    this.onSecure        = null; 
    this.onError         = null; 

    if (this.cert && this.key) {
      const match = CertificateValidator.validateKeyMatch(this.cert, this.key);
      if (!match.valid) throw new Error(`[CONFIG_ERROR] Sertifika ve Anahtar eşleşmiyor: ${match.error}`);
    }

    log.info(`${this.roleLog} TLS Started Transport: ${this.transport.toUpperCase()}`);
  }

  _getEmptyHash() {
    return this.hashAlgo === 'sha384' ? sha384(Buffer.alloc(0)) : sha256(Buffer.alloc(0));
  }

  _applyCipherSuite(suiteId) {
    const info = SUITE_INFO[suiteId];
    if (!info) throw Object.assign(new Error(`Desteklenmeyen şifreleme paketi: 0x${suiteId.toString(16)}`), { alertCode: TLS_ALERTS.HANDSHAKE_FAILURE });
    this.cipherSuite = suiteId;
    this.hashAlgo    = info.hash;
    this.hashLen     = info.hashLen;
    this.keyLen      = info.keyLen;
    log.debug(`${this.roleLog} [CIPHER] Şifreleme takımı seçildi: ${info.name}`);
  }

  processHandshakeData(data) {
    this.receiveCryptoData(ENCRYPTION_LEVEL.INITIAL, this.cryptoStreams[ENCRYPTION_LEVEL.INITIAL].nextExpected, data);
  }

  receiveCryptoData(level, offset, data) {
    const stream = this.cryptoStreams[level];
    if (!stream) return;
    stream.received.set(offset, data);

    while (stream.received.has(stream.nextExpected)) {
      const fragment = stream.received.get(stream.nextExpected);
      stream.received.delete(stream.nextExpected);
      stream.buffer = Buffer.concat([stream.buffer, fragment]);
      stream.nextExpected += fragment.length;
    }
    this._processMessages(level);
  }

  _processMessages(level) {
    const stream = this.cryptoStreams[level];
    let buf = stream.buffer;

    while (buf.length >= 4) {
      const msgType = buf[0];
      const msgLen  = (buf[1] << 16) | (buf[2] << 8) | buf[3];
      if (buf.length < 4 + msgLen) break;

      const fullMsg = buf.subarray(0, 4 + msgLen);
      buf = buf.subarray(4 + msgLen);

      if (msgType !== TLS_HANDSHAKE.NEW_SESSION_TICKET) {
        this._addToTranscript(fullMsg);
      }
      this._handleMessage(level, msgType, fullMsg.subarray(4));
    }
    stream.buffer = buf;
  }

  _handleMessage(level, type, body) {
    try {
      if (!this.isServer && type === TLS_HANDSHAKE.NEW_SESSION_TICKET) {
        log.trace(`${this.roleLog} [STATE] NewSessionTicket received (Resumption PSK).`);
        this._parseNewSessionTicket(body);
        return;
      }
      switch (type) {
        case TLS_HANDSHAKE.CLIENT_HELLO:
          log.info(`${this.roleLog} [STATE] ClientHello Received`);
          if (this.isServer) this._handleClientHello(body);
          break;
        case TLS_HANDSHAKE.SERVER_HELLO:
          log.info(`${this.roleLog} [STATE] ServerHello Received`);
          if (!this.isServer) this._handleServerHello(body);
          break;
        case TLS_HANDSHAKE.ENCRYPTED_EXTENSIONS:
          log.debug(`${this.roleLog} [STATE] EncryptedExtensions Received`);
          this._handleEncryptedExtensions(body);
          break;
        case TLS_HANDSHAKE.CERTIFICATE_REQUEST:
          log.debug(`${this.roleLog} [STATE] CertificateRequest Received`);
          if (!this.isServer) this._handleCertificateRequest(body);
          break;
        case TLS_HANDSHAKE.CERTIFICATE:
          log.debug(`${this.roleLog} [STATE] Certificate Zinciri Reveiced`);
          this._handleCertificate(body);
          break;
        case TLS_HANDSHAKE.CERTIFICATE_VERIFY:
          log.debug(`${this.roleLog} [STATE] CertificateVerify Reveiced`);
          this._handleCertificateVerify(body);
          break;
        case TLS_HANDSHAKE.FINISHED:
          log.debug(`${this.roleLog} [STATE] Finished Mesajı Reveiced`);
          this._handleFinished(level, body);
          break;
        default:
          throw Object.assign(new Error(`Bilinmeyen Mesaj Tipi: ${type}`), { alertCode: TLS_ALERTS.UNEXPECTED_MESSAGE });
      }
    } catch (err) {
      log.error(`${this.roleLog} [TLS_FATAL] Mesaj İşleme Hatası (Tip=${type}):`, err.message);
      this._fatalError(err, err.alertCode || TLS_ALERTS.HANDSHAKE_FAILURE);
    }
  }
_parseNewSessionTicket(body) {
  // RFC 8446 §4.6.1: NewSessionTicket ayrıştır
  try {
    let off = 0;

    if (off + 4 > body.length) return;
    const lifetime = body.readUInt32BE(off); off += 4;

    if (off + 4 > body.length) return;
    const ageAdd = body.readUInt32BE(off); off += 4;

    if (off >= body.length) return;
    const nonceLen = body[off++];
    if (off + nonceLen > body.length) return;
    const nonce = body.subarray(off, off + nonceLen); off += nonceLen;

    if (off + 2 > body.length) return;
    const ticketLen = body.readUInt16BE(off); off += 2;
    if (off + ticketLen > body.length) return;
    const ticket = Buffer.from(body.subarray(off, off + ticketLen)); off += ticketLen;

    // Client-side PSK türetimi (RFC 8446 §7.5):
    //   resumption_master_secret = HKDF-Expand-Label(master_secret, "res master", transcript_hash, hashLen)
    //   PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", nonce, hashLen)
    if (!this.masterSecret) {
      log.warn(`${this.roleLog} [NST] masterSecret yok, ticket skip`);
      return;
    }

    const transcriptHash    = this._getTranscriptHash();
    const resumptionMaster  = hkdfExpandLabel(
      this.hashAlgo, this.masterSecret, 'res master', transcriptHash, this.hashLen
    );
    const psk = hkdfExpandLabel(
      this.hashAlgo, resumptionMaster, 'resumption', nonce, this.hashLen
    );

    const ticketData = {
      ticket,
      psk,
      ageAdd,
      cipherSuite: this.cipherSuite,
      iat:         Date.now(),
      lifetime:    lifetime * 1000, // ms
      serverName:  this.serverName,
      alpn:        this.selectedAlpn || (this.alpn && this.alpn[0]),
    };

    log.info(`${this.roleLog} [NST] Session ticket alındı, PSK türetildi (lifetime=${lifetime}s, suite=0x${this.cipherSuite.toString(16)})`);
    this.emit('sessionTicket', ticketData);

  } catch (e) {
    log.warn(`${this.roleLog} [NST] Parse hatası: ${e.message}`);
  }
}
  _handleClientHello(body) {
    let off = 2;
    if (off + 32 > body.length) throw Object.assign(new Error('Missing ClientHello (random)'), { alertCode: TLS_ALERTS.DECODE_ERROR });
    this.clientRandom = body.subarray(off, off + 32); off += 32;

    const sidLen = body[off++];
    if (off + sidLen > body.length) throw Object.assign(new Error('Missing ClientHello (session id)'), { alertCode: TLS_ALERTS.DECODE_ERROR });
    
    // DÜZELTME: Session-ID'yi QUIC için sıfırlamıyoruz. OpenSSL'in "Session-ID: XXX" basması için aynen kabul edip yankılayacağız.
    this.clientSessionId = body.subarray(off, off + sidLen); 
    off += sidLen;

    if (off + 2 > body.length) throw Object.assign(new Error('Missing ClientHello (ciphers len)'), { alertCode: TLS_ALERTS.DECODE_ERROR });
    const csLen = body.readUInt16BE(off); off += 2;
    
    const clientCiphers = [];
    for (let i = 0; i < csLen; i += 2) clientCiphers.push(body.readUInt16BE(off + i));
    off += csLen;

    const chosen = this.allowedCiphers.find(c => clientCiphers.includes(c));
    if (!chosen) throw Object.assign(new Error('Shared encryption package error'), { alertCode: TLS_ALERTS.HANDSHAKE_FAILURE });
    this._applyCipherSuite(chosen);

    const compLen = body[off++]; off += compLen;

    if (off + 2 <= body.length) {
      const extLen = body.readUInt16BE(off); off += 2;
      this._parseExtensions(body.subarray(off, off + extLen), false);
    }

    // DÜZELTME: PSK doğrulandıysa 0-RTT early key'leri üret ve QUIC katmanına ilet
    if (this.resumptionPsk && this.enable0rtt) {
      const { deriveZeroRTTKeys } = require('./zero-rtt');
      const clientHelloHash = this._getTranscriptHash();
      const early = deriveZeroRTTKeys(this.hashAlgo, this.resumptionPsk, clientHelloHash, this.keyLen);
      
      // Biletin içindeki önceden uzlaşılan ALPN'i atayalım
      if (this.resumedMeta && this.resumedMeta.alpn) {
        this.selectedAlpn = this.resumedMeta.alpn;
      }
      
      this.emit('earlyKeys', {
        keys: early.keys,
        suite: SUITE_INFO[this.cipherSuite].aead
      });
    }

    const isTCP = this.transport === 'tcp' || typeof this.onHandshakeData === 'function';
    
    if (isTCP) {
      this._tcpServerHandshakeFlight();
    } else {
      this.state = 'GENERATING_SERVER_HELLO';
    }
  }

  _handleServerHello(body) {
    let off = 2;
    this.serverRandom = body.subarray(off, off + 32); off += 32;
    const sidLen = body[off++]; off += sidLen;
    const serverCipher = body.readUInt16BE(off); off += 2;
    this._applyCipherSuite(serverCipher);
    off += 1; 

    if (off + 2 <= body.length) {
      const extLen = body.readUInt16BE(off); off += 2;
      this._parseExtensions(body.subarray(off, off + extLen), true);
    }

    const sharedSecret = this._computeSharedSecret();
    this._deriveHandshakeKeys(sharedSecret);
    this.state = 'WAIT_ENCRYPTED_EXTENSIONS';
  }

  _handleEncryptedExtensions(body) {
    let off = 0;
    const extLen = body.readUInt16BE(off); off += 2;
    this._parseExtensions(body.subarray(off, off + extLen), true);
    this.state = 'WAIT_CERTIFICATE';
  }

  _handleCertificateRequest(body) {
    const ctxLen = body[0];
    this._certRequestContext = body.subarray(1, 1 + ctxLen);
    this.state = 'WAIT_CERTIFICATE';
    this.emit('certificateRequest');
  }

  _handleCertificate(body) {
    this.peerCertificate = body;
    let off = 0;
    const ctxLen = body[off++]; off += ctxLen;
    const certsLen = (body[off] << 16) | (body[off + 1] << 8) | body[off + 2]; off += 3;
    const end = off + certsLen;

    while (off + 3 <= end) {
      const certLen = (body[off] << 16) | (body[off + 1] << 8) | body[off + 2]; off += 3;
      if (off + certLen > end) break;
      off += certLen;
      if (off + 2 <= end) {
        const xLen = body.readUInt16BE(off); off += 2 + xLen;
      }
    }
    this.state = 'WAIT_CERTIFICATE_VERIFY';
  }

  _handleCertificateVerify(body) {
    this.state = 'WAIT_FINISHED';
  }

  _handleFinished(level, body) {
    const expectedSecret = this.isServer ? this.clientHandshakeSecret : this.serverHandshakeSecret;
    if (expectedSecret) {
      const finishedKey  = hkdfExpandLabel(this.hashAlgo, expectedSecret, 'finished', Buffer.alloc(0), this.hashLen);
      const expectedData = hmac(this.hashAlgo, finishedKey, this._getTranscriptHashBeforeLast());
      
      if (!timingSafeEqual(body, expectedData)) {
        throw Object.assign(new Error('Finished message verification failed (MAC mismatch)'), { alertCode: TLS_ALERTS.BAD_RECORD_MAC });
      }
      log.trace(`${this.roleLog} [HANDSHAKE] Finished MAC successfully verified.`);
    }

    const secureMeta = {
      cipher:  SUITE_INFO[this.cipherSuite]?.name,
      alpn:    this.selectedAlpn,
      version: 'TLSv1.3',
    };

    if (this.isServer) {
      this.state = 'CONNECTED';
      log.info(`${this.roleLog} [CONNECTION] Handshake complete, context secure ALPN: ${this.selectedAlpn || 'Yok'}`);
      
      if (this.transport === 'tcp' && this.onHandshakeData) {
        this.onHandshakeData('SET_WRITE_KEYS', this._tcpAppKeys.server, false);
        this.onHandshakeData('SET_READ_KEYS',  this._tcpAppKeys.client, false);
      }

      if (this.onSecure) this.onSecure(secureMeta);
      this.emit('secure', secureMeta);
      this.emit('connected');
      
      if (this.enable0rtt) {
        log.debug(`${this.roleLog} [TICKET] Client 1-RTT Post-Handshake NewSessionTicket generated`);
        // DÜZELTME: Biletler nextTick'e bırakılmadan, senkron bir şekilde anında üretilip stream'e veriliyor.
        this._sendNewSessionTicket();
        this._sendNewSessionTicket(); 
      }
    } else {
      this._deriveApplicationKeys();
      const clientMsgs = [];
      const clientFinished = this._buildFinished(this.clientHandshakeSecret);
      this._addToTranscript(clientFinished);
      clientMsgs.push(clientFinished);

      this.state = 'CONNECTED';
      log.info(`${this.roleLog} [CONNECTION] Handshake complete, context secure ALPN: ${this.selectedAlpn || 'Yok'}`);

      if (this.transport === 'tcp' && this.onHandshakeData) {
        this.onHandshakeData('SET_WRITE_KEYS', this._tcpAppKeys.client, false);
        this.onHandshakeData('SET_READ_KEYS',  this._tcpAppKeys.server, false);
        this.onHandshakeData(22, Buffer.concat(clientMsgs), true);
      }

      if (this.onSecure) this.onSecure(secureMeta);
      this.emit('secure', secureMeta);
      
      this.emit('clientFinished', { level: ENCRYPTION_LEVEL.HANDSHAKE, data: Buffer.concat(clientMsgs) });
      this.emit('connected');
    }
  }

  _computeSharedSecret() {
    if (this.negotiatedGroup === GROUP_X25519_MLKEM768 || this.negotiatedGroup === PQC_GROUP_ALT) {
      if (this.isServer) {
        let clientMlkemEk, clientX25519Pub;

        if (this.negotiatedGroup === GROUP_X25519_MLKEM768) {
          clientMlkemEk   = this.peerPublicKey.subarray(0, 1184);
          clientX25519Pub = this.peerPublicKey.subarray(1184, 1216);
        } else {
          clientX25519Pub = this.peerPublicKey.subarray(0, 32);
          clientMlkemEk   = this.peerPublicKey.subarray(32, 1216);
        }

        const rawX25519 = x25519(this.x25519Key.privateKey, clientX25519Pub);
        const x25519Shared = Buffer.from(rawX25519); 

        const encResult = mlkemEncapsulate(clientMlkemEk);
        const mlkemShared = Buffer.from(encResult.ss);
        const ciphertext = Buffer.from(encResult.ct || encResult.ciphertext); 

        const x25519PubRaw = Buffer.from(this.x25519Key.publicKeyRaw || this.x25519Key.publicKey);
        
        if (this.negotiatedGroup === GROUP_X25519_MLKEM768) {
          this.serverSharePayload = Buffer.concat([ciphertext, x25519PubRaw]); 
        } else {
          this.serverSharePayload = Buffer.concat([x25519PubRaw, ciphertext]); 
        }
        
        this._hybridSharedSecret = Buffer.concat([mlkemShared, x25519Shared]);
        log.trace(`${this.roleLog} [CRYPTO] Hybrid Shared Secret Derived`);
        return this._hybridSharedSecret;
      } else {
        let serverMlkemCt, serverX25519Pub;

        if (this.negotiatedGroup === GROUP_X25519_MLKEM768) {
          serverMlkemCt   = this.peerPublicKey.subarray(0, 1088);
          serverX25519Pub = this.peerPublicKey.subarray(1088, 1120);
        } else {
          serverX25519Pub = this.peerPublicKey.subarray(0, 32);
          serverMlkemCt   = this.peerPublicKey.subarray(32, 1120);
        }
        
        const x25519Shared = Buffer.from(x25519(this.x25519Key.privateKey, serverX25519Pub));
const decResult = mlkemDecapsulate(this.mlkemKey.dk, serverMlkemCt);
        const mlkemShared  = Buffer.from(decResult.ss || decResult);
        
        this._hybridSharedSecret = Buffer.concat([mlkemShared, x25519Shared]);
        log.trace(`${this.roleLog} [CRYPTO] Hibrit Shared Secret Çözümlendi (PQC+Klasik).`);
        return this._hybridSharedSecret;
      }
    }

    if (this.negotiatedGroup === GROUP_X25519) {
      const pubRaw = Buffer.from(this.x25519Key.publicKeyRaw || this.x25519Key.publicKey);
      if (this.isServer) this.serverSharePayload = pubRaw;
      return Buffer.from(x25519(this.x25519Key.privateKey, this.peerPublicKey));
    }
    throw Object.assign(new Error('Üzerinde anlaşılan bir anahtar değişim grubu bulunamadı'), { alertCode: TLS_ALERTS.HANDSHAKE_FAILURE });
  }

  _deriveTrafficKeys(secret) {
    const keyLabel = this.transport === 'quic' ? 'quic key' : 'key';
    const ivLabel  = this.transport === 'quic' ? 'quic iv'  : 'iv';

    const key = hkdfExpandLabel(this.hashAlgo, secret, keyLabel, Buffer.alloc(0), this.keyLen);
    const iv  = hkdfExpandLabel(this.hashAlgo, secret, ivLabel, Buffer.alloc(0), 12);
    
    if (this.transport === 'quic') {
      const hp = hkdfExpandLabel(this.hashAlgo, secret, 'quic hp', Buffer.alloc(0), this.keyLen);
      return { key, iv, hp };
    }

    return { key, iv };
  }

  _deriveHandshakeKeys(sharedSecret) {
    // YENİ DÜZELTME: Eğer PSK (Resumption) varsa IKM olarak onu kullan, yoksa boş buffer kullan.
    const ikm = this.resumptionPsk ? this.resumptionPsk : Buffer.alloc(this.hashLen);

    this.earlySecret = hkdfExtract(
      this.hashAlgo,
      Buffer.alloc(this.hashLen),
      ikm // ESKİDEN BURASI Buffer.alloc(this.hashLen) İDİ.
    );

    const derivedSecret = hkdfExpandLabel(
      this.hashAlgo,
      this.earlySecret,
      'derived',
      this._getEmptyHash(),
      this.hashLen
    );

    this.handshakeSecret = hkdfExtract(this.hashAlgo, derivedSecret, sharedSecret);

    const th = this._getTranscriptHash();
    this.clientHandshakeSecret = hkdfExpandLabel(this.hashAlgo, this.handshakeSecret, 'c hs traffic', th, this.hashLen);
    this.serverHandshakeSecret = hkdfExpandLabel(this.hashAlgo, this.handshakeSecret, 's hs traffic', th, this.hashLen);

    this.keys[ENCRYPTION_LEVEL.HANDSHAKE] = {
      clientKeys: this._deriveTrafficKeys(this.clientHandshakeSecret),
      serverKeys: this._deriveTrafficKeys(this.serverHandshakeSecret),
    };
    
    log.debug(`${this.roleLog} [CRYPTO] Handshake (0-RTT -> 1-RTT) Traffic Keys Created`);

    this.emit('handshakeKeys', {
      level:  ENCRYPTION_LEVEL.HANDSHAKE,
      cipher: SUITE_INFO[this.cipherSuite],
      ...this.keys[ENCRYPTION_LEVEL.HANDSHAKE],
    });
  }

  _deriveApplicationKeys() {
    const derivedSecret = hkdfExpandLabel(this.hashAlgo, this.handshakeSecret, 'derived', this._getEmptyHash(), this.hashLen);
    this.masterSecret = hkdfExtract(this.hashAlgo, derivedSecret, Buffer.alloc(this.hashLen, 0));

    const th = this._getTranscriptHash();
    this.clientAppSecret = hkdfExpandLabel(this.hashAlgo, this.masterSecret, 'c ap traffic', th, this.hashLen);
    this.serverAppSecret = hkdfExpandLabel(this.hashAlgo, this.masterSecret, 's ap traffic', th, this.hashLen);

    this.keys[ENCRYPTION_LEVEL.ONE_RTT] = {
      clientKeys: this._deriveTrafficKeys(this.clientAppSecret),
      serverKeys: this._deriveTrafficKeys(this.serverAppSecret),
    };
    
    log.debug(`${this.roleLog} [CRYPTO] Application (1-RTT) Traffic Keys Created`);

    this.emit('applicationKeys', {
      level:  ENCRYPTION_LEVEL.ONE_RTT,
      cipher: SUITE_INFO[this.cipherSuite],
      ...this.keys[ENCRYPTION_LEVEL.ONE_RTT],
    });
  }

  _buildServerHandshakeFlight() {
    const sharedSecret = this._computeSharedSecret();

    if (!this.serverRandom) {
      this.serverRandom = randomBytes(32);
    }

    const shExts = [];
    const sv = Buffer.alloc(2);
    sv.writeUInt16BE(TLS_VERSION_13, 0);
    shExts.push(_buildExtension(0x002b, sv));

    const pubKey = this.serverSharePayload;
    const ksData = Buffer.alloc(4 + pubKey.length);
    ksData.writeUInt16BE(this.negotiatedGroup, 0);
    ksData.writeUInt16BE(pubKey.length, 2);
    pubKey.copy(ksData, 4);
    shExts.push(_buildExtension(0x0033, ksData));

    // ServerHello içine seçilen pre_shared_key indeksini ekle (0. indeks)
    if (this.resumptionPsk) {
      const pskExt = Buffer.alloc(2);
      pskExt.writeUInt16BE(0, 0); 
      shExts.push(_buildExtension(0x0029, pskExt));
    }

    const shExtBuf  = Buffer.concat(shExts);
    const sessionId = this.clientSessionId || Buffer.alloc(0);

    const shBody = Buffer.concat([
      Buffer.from([0x03, 0x03]),
      this.serverRandom, 
      Buffer.from([sessionId.length]),
      sessionId,
      Buffer.from([this.cipherSuite >> 8, this.cipherSuite & 0xff]),
      Buffer.from([0x00]),
      Buffer.alloc(2),
      shExtBuf,
    ]);
    shBody.writeUInt16BE(shExtBuf.length, shBody.length - shExtBuf.length - 2);

    const shMsg = _wrapHandshake(TLS_HANDSHAKE.SERVER_HELLO, shBody);
    this._addToTranscript(shMsg);
    
    this._deriveHandshakeKeys(sharedSecret);

    const eeExts = [];
    
    // YENİ DÜZELTME: 0-RTT onayını (early_data extension) EncryptedExtensions içine ekle
    if (this.resumptionPsk && this.enable0rtt) {
      eeExts.push(_buildExtension(0x002a, Buffer.alloc(0)));
    }

    if (this.selectedAlpn) {
      const sel     = Buffer.from(this.selectedAlpn, 'ascii');
      const alpnBuf = Buffer.alloc(2 + 1 + sel.length);
      alpnBuf.writeUInt16BE(1 + sel.length, 0);
      alpnBuf[2] = sel.length;
      sel.copy(alpnBuf, 3);
      eeExts.push(_buildExtension(0x0010, alpnBuf));
    }
    
    if (this.transport === 'quic' && this.transportParams.length > 0) {
      eeExts.push(_buildExtension(QUIC_TP_EXTENSION, this.transportParams));
    }
    
    const eeBody = Buffer.concat(eeExts);
    const eeBuf  = Buffer.alloc(2 + eeBody.length);
    eeBuf.writeUInt16BE(eeBody.length, 0);
    eeBody.copy(eeBuf, 2);
    const eeMsg = _wrapHandshake(TLS_HANDSHAKE.ENCRYPTED_EXTENSIONS, eeBuf);
    this._addToTranscript(eeMsg);

    const handshakeMsgs = [eeMsg];

    if (this.requestCert && !this.resumptionPsk) {
      const crMsg = this._buildCertificateRequest();
      this._addToTranscript(crMsg);
      handshakeMsgs.push(crMsg);
    }

    // YENİ DÜZELTME: PSK (0-RTT) kabul edildiyse Sertifika GÖNDERİLMEZ.
    if (this.cert && !this.resumptionPsk) {
      const certMsg = this._buildCertificateMessage(this.cert);
      this._addToTranscript(certMsg);
      handshakeMsgs.push(certMsg);

      const cvMsg = this._buildCertificateVerify(this.key, true);
      this._addToTranscript(cvMsg);
      handshakeMsgs.push(cvMsg);
    }

    const finMsg = this._buildFinished(this.serverHandshakeSecret);
    this._addToTranscript(finMsg);
    handshakeMsgs.push(finMsg);

    log.debug(`${this.roleLog} [STATE] Server Handshake Flight (Hello -> Finished) Completed`);

    return {
      shMsg,
      handshakeData: Buffer.concat(handshakeMsgs)
    };
  }

  generateServerHello() {
    const flight = this._buildServerHandshakeFlight();
    this._deriveApplicationKeys();
    this.state = 'WAIT_CLIENT_FINISHED';

    return {
      serverHello: { level: ENCRYPTION_LEVEL.INITIAL, data: flight.shMsg },
      handshakeData: { level: ENCRYPTION_LEVEL.HANDSHAKE, data: flight.handshakeData }
    };
  }

  _tcpServerHandshakeFlight() {
    const flight = this._buildServerHandshakeFlight();

    this.onHandshakeData(22, flight.shMsg, false);
    this.onHandshakeData('CCS', null, false);
    
    this.onHandshakeData('SET_WRITE_KEYS', {
      key:    this.keys[ENCRYPTION_LEVEL.HANDSHAKE].serverKeys.key,
      iv:     this.keys[ENCRYPTION_LEVEL.HANDSHAKE].serverKeys.iv,
      cipher: SUITE_INFO[this.cipherSuite].aead, 
    }, false);
    this.onHandshakeData('SET_READ_KEYS', {
      key:    this.keys[ENCRYPTION_LEVEL.HANDSHAKE].clientKeys.key,
      iv:     this.keys[ENCRYPTION_LEVEL.HANDSHAKE].clientKeys.iv,
      cipher: SUITE_INFO[this.cipherSuite].aead,
    }, false);

    this.onHandshakeData(22, flight.handshakeData, true);

    this._stashTcpApplicationKeys();
    this.state = 'WAIT_CLIENT_FINISHED';
  }

  _stashTcpApplicationKeys() {
    this._deriveApplicationKeys();
    
    this._tcpAppKeys = {
      server: {
        key:    this.keys[ENCRYPTION_LEVEL.ONE_RTT].serverKeys.key,
        iv:     this.keys[ENCRYPTION_LEVEL.ONE_RTT].serverKeys.iv,
        cipher: SUITE_INFO[this.cipherSuite].aead,
      },
      client: {
        key:    this.keys[ENCRYPTION_LEVEL.ONE_RTT].clientKeys.key,
        iv:     this.keys[ENCRYPTION_LEVEL.ONE_RTT].clientKeys.iv,
        cipher: SUITE_INFO[this.cipherSuite].aead,
      },
    };
  }

  _sendNewSessionTicket() {
    const transcriptHash    = this._getTranscriptHash();
    const resumptionSecret  = hkdfExpandLabel(this.hashAlgo, this.masterSecret, 'res master', transcriptHash, this.hashLen);
    const ticketNonce       = randomBytes(16);
    const psk               = hkdfExpandLabel(this.hashAlgo, resumptionSecret, 'resumption', ticketNonce, this.hashLen);

    const meta = Buffer.from(JSON.stringify({
      suite: this.cipherSuite,
      alpn:  this.selectedAlpn || this.alpn[0],
      iat:   Date.now(),
      sni:   this.peerServerName || this.serverName,
    }), 'utf8');

    const iv = randomBytes(12);
    const payload = Buffer.concat([psk, meta]);
    const ctWithTag = gcmEncrypt(this._ticketKey, iv, payload, Buffer.alloc(0));
    const ticket = Buffer.concat([iv, ctWithTag.ciphertext || ctWithTag, ctWithTag.tag || Buffer.alloc(0)]); 
    
    const ageAdd = randomBytes(4).readUInt32BE(0);

    const extBuf = Buffer.alloc(8);
    extBuf.writeUInt16BE(0x002a, 0);
    extBuf.writeUInt16BE(4, 2);
    extBuf.writeUInt32BE(this.maxEarlyData, 4);

    const body = Buffer.alloc(4 + 4 + 1 + ticketNonce.length + 2 + ticket.length + 2 + extBuf.length);
    let off = 0;
    body.writeUInt32BE(this.ticketLifetime, off); off += 4;
    body.writeUInt32BE(ageAdd, off);              off += 4;
    body.writeUInt8(ticketNonce.length, off);     off += 1;
    ticketNonce.copy(body, off);                  off += ticketNonce.length;
    body.writeUInt16BE(ticket.length, off);       off += 2;
    ticket.copy(body, off);                       off += ticket.length;
    body.writeUInt16BE(extBuf.length, off);       off += 2;
    extBuf.copy(body, off);

    const nstMsg = _wrapHandshake(TLS_HANDSHAKE.NEW_SESSION_TICKET, body);
    
    if (this.transport === 'tcp' && this.onHandshakeData) {
      this.onHandshakeData(22, nstMsg, true);
    } else {
      this.emit('postHandshakeCrypto', { level: ENCRYPTION_LEVEL.ONE_RTT, data: nstMsg });
    }
  }

  _buildFinished(baseSecret) {
    const finishedKey  = hkdfExpandLabel(this.hashAlgo, baseSecret, 'finished', Buffer.alloc(0), this.hashLen);
    const verifyData   = hmac(this.hashAlgo, finishedKey, this._getTranscriptHash());
    return _wrapHandshake(TLS_HANDSHAKE.FINISHED, verifyData);
  }

  _buildCertificateRequest() {
    const context = randomBytes(1);
    this._certRequestContext = context;

    const sigAlgs = Buffer.alloc(6);
    sigAlgs.writeUInt16BE(4, 0);
    sigAlgs.writeUInt16BE(SIG_RSA_PSS_RSAE_SHA256, 2);
    sigAlgs.writeUInt16BE(SIG_ECDSA_SECP256R1_SHA256, 4);
    const sigExt = _buildExtension(0x000d, sigAlgs);

    const extBuf = Buffer.concat([sigExt]);
    const body = Buffer.concat([Buffer.from([context.length]), context, Buffer.alloc(2), extBuf]);
    body.writeUInt16BE(extBuf.length, 1 + context.length);
    return _wrapHandshake(TLS_HANDSHAKE.CERTIFICATE_REQUEST, body);
  }

  _buildCertificateMessage(certPem, requestContext) {
    const pemStr = certPem.toString();
    const regex  = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/g;
    let match;
    const certEntries = [];
    let totalLength   = 0;

    while ((match = regex.exec(pemStr)) !== null) {
      const der   = Buffer.from(match[1].replace(/[\r\n\s]+/g, ''), 'base64');
      const entry = Buffer.alloc(3 + der.length + 2);
      entry.writeUIntBE(der.length, 0, 3);
      der.copy(entry, 3);
      entry.writeUInt16BE(0, 3 + der.length);
      certEntries.push(entry);
      totalLength += entry.length;
    }

    const ctx = requestContext || Buffer.alloc(0);
    const certsListBuf = Buffer.alloc(3);
    certsListBuf.writeUIntBE(totalLength, 0, 3);

    const body = Buffer.concat([Buffer.from([ctx.length]), ctx, certsListBuf, ...certEntries]);
    return _wrapHandshake(TLS_HANDSHAKE.CERTIFICATE, body);
  }

  _buildCertificateVerify(keyPem, isServer) {
    const content = Buffer.concat([
      Buffer.alloc(64, 0x20),
      Buffer.from(isServer ? 'TLS 1.3, server CertificateVerify\x00' : 'TLS 1.3, client CertificateVerify\x00', 'ascii'),
      this._getTranscriptHash(),
    ]);

    const privKeyStr = Buffer.isBuffer(keyPem) ? keyPem.toString('utf8') : keyPem;
    const isRsa      = privKeyStr.includes('RSA PRIVATE KEY') || privKeyStr.includes('BEGIN PRIVATE KEY');

    let sigAlg, signature;
    if (isRsa) {
      sigAlg = SIG_RSA_PSS_RSAE_SHA256;
      let privKey;
      if (privKeyStr.includes('RSA PRIVATE KEY')) privKey = pemToRsaPriv(privKeyStr);
      else {
        const b64    = privKeyStr.replace(/-----.+-----|\n/g, '');
        const der    = Buffer.from(b64, 'base64');
        const rsaB64 = der.subarray(26).toString('base64').match(/.{1,64}/g).join('\n');
        privKey      = pemToRsaPriv(`-----BEGIN RSA PRIVATE KEY-----\n${rsaB64}\n-----END RSA PRIVATE KEY-----`);
      }
      signature = _rsaSignPss(privKey, content);
    } else {
      const privKeyInt = pemToEcPriv(privKeyStr).privateKey;
      const clientSupportsMldsa = this.clientSigAlgs.includes(SIG_ML_DSA_65);

      if (isServer && this.mldsaKeys && clientSupportsMldsa) {
        sigAlg         = SIG_ML_DSA_65;
        const ecSig    = ecdsaSign('P-256', privKeyInt, content, 'sha256');
        const mlSig    = mldsaSign(this.mldsaKeys.sk, content);
        const buf      = Buffer.alloc(2 + ecSig.length + 3 + mlSig.length);
        buf.writeUInt16BE(ecSig.length, 0);
        ecSig.copy(buf, 2);
        buf.writeUInt8((mlSig.length >> 16) & 0xff, 2 + ecSig.length);
        buf.writeUInt16BE(mlSig.length & 0xffff, 3 + ecSig.length);
        mlSig.copy(buf, 5 + ecSig.length);
        signature = buf;
        log.info(`${this.roleLog} [SIGNATURE] The verification was signed using the ML-DSA-65 hybrid algorithm`);
      } else {
        sigAlg    = SIG_ECDSA_SECP256R1_SHA256;
        signature = ecdsaSign('P-256', privKeyInt, content, 'sha256');
        if (isServer && this.mldsaKeys) {
          log.warn(`${this.roleLog} [SIGNATURE_WARN] ECDSA fallback was used instead of PQC signature because the client does not support it`);
        }
      }
    }

    const body = Buffer.alloc(4 + signature.length);
    body.writeUInt16BE(sigAlg, 0);
    body.writeUInt16BE(signature.length, 2);
    signature.copy(body, 4);
    return _wrapHandshake(TLS_HANDSHAKE.CERTIFICATE_VERIFY, body);
  }

  _parseExtensions(buf, isServerSide) {
    let off = 0;
    while (off + 4 <= buf.length) {
      const type = buf.readUInt16BE(off); off += 2;
      const len  = buf.readUInt16BE(off); off += 2;
      if (off + len > buf.length) break;
      const data = buf.subarray(off, off + len);
      off += len;

      // YENİ: İstemciden gelen SNI (Server Name) bilgisini oku
      if (type === 0x0000 && this.isServer) {
        let p = 2; // liste uzunluğunu atla
        if (p < data.length) {
          const nameType = data[p++];
          if (nameType === 0) { // 0 = host_name
            const nameLen = data.readUInt16BE(p); p += 2;
            this.peerServerName = data.subarray(p, p + nameLen).toString('ascii');
            log.debug(`${this.roleLog} [SNI] Parsed: ${this.peerServerName}`);
          }
        }
      } else if (type === 0x0033) {
        this._parseKeyShare(data, isServerSide);
      } else if (type === 0x000d && this.isServer) {
        try {
          const algsLen = data.readUInt16BE(0);
          this.clientSigAlgs = [];
          for (let i = 0; i < algsLen; i += 2) {
            this.clientSigAlgs.push(data.readUInt16BE(2 + i));
          }
        } catch (e) {
          log.warn(`${this.roleLog} [EXTENSION_WARN] İmza algoritmaları parse edilirken hata oluştu.`);
        }
      } else if (type === 0x0010 && this.isServer) {
        if (this.isServer) {
          let p = 2; // list_len atla
          while (p < data.length) {
            const aLen = data[p++];
            this.clientAlpns.push(data.subarray(p, p + aLen).toString('ascii'));
            p += aLen;
          }
        } else {
          // Server'ın seçtiği ALPN — EncryptedExtensions'dan gelir
          // Wire format: list_len(2) | proto_len(1) | proto_bytes
          if (data.length >= 3) {
            const aLen = data[2]; // data[0..1]=list_len, data[2]=proto_len
            if (3 + aLen <= data.length) {
              this.selectedAlpn = data.subarray(3, 3 + aLen).toString('ascii');
              log.debug(`${this.roleLog} [ALPN] Server selected: ${this.selectedAlpn}`);
            }
          }
        }
      } else if (type === 0x0029 && !isServerSide) { 
        try {
          const idListLen = data.readUInt16BE(0);
          let p = 2;
          if (p < 2 + idListLen) {
            const idLen = data.readUInt16BE(p); p += 2;
            const identity = data.subarray(p, p + idLen);
            
            const { derivePSK } = require('./zero-rtt');
            const res = derivePSK(this.hashAlgo || 'sha256', this._ticketKey, identity);
            if (res && res.psk) {
              this.resumptionPsk = res.psk;
              this.resumedMeta = res.meta;
              log.info(`${this.roleLog} [0-RTT] The PSK ticket has been verified and accepted. (SNI: ${res.meta.sni})`);
            }
          }
        } catch (e) {
          log.warn(`${this.roleLog} [0-RTT] pre_shared_key An error occurred during resolution.`);
        }
      }
    }

    if (this.isServer) {
      if (this.clientAlpns.length > 0) {
        const inter = this.clientAlpns.filter(a => this.alpn.includes(a));
        if (inter.length === 0) {
          log.error(`${this.roleLog} [ALPN_FATAL] No common application protocol found. (Client: [${this.clientAlpns.join(', ')}], Server: [${this.alpn.join(', ')}]).`);
          throw Object.assign(new Error('no_application_protocol'), { alertCode: TLS_ALERTS.NO_APPLICATION_PROTOCOL });
        }
        this.selectedAlpn = inter[0];
        log.debug(`${this.roleLog} [ALPN] The protocol was successfully agreed upon.: ${this.selectedAlpn}`);
      } else if (this.transport === 'quic') {
        log.error(`${this.roleLog} [ALPN_FATAL] QUIC requires the ALPN extension. The client did not send ALPN.`);
        throw Object.assign(new Error('no_application_protocol (QUIC requires ALPN)'), { alertCode: TLS_ALERTS.NO_APPLICATION_PROTOCOL });
      }
    }
  }
  generateClientHello() {
  if (this.isServer) throw new Error('[TLS] generateClientHello() is client-only');

  this.clientRandom    = randomBytes(32);
  this.clientSessionId = randomBytes(32); // Middlebox compat (RFC 8446 §4.1.2)

  const extensions = [];

  // ── SNI (0x0000) ────────────────────────────────────────────────────────────
  {
    const hostBuf   = Buffer.from(this.serverName, 'ascii');
    const nameEntry = Buffer.allocUnsafe(3 + hostBuf.length);
    nameEntry[0] = 0x00; // host_name
    nameEntry.writeUInt16BE(hostBuf.length, 1);
    hostBuf.copy(nameEntry, 3);
    const list = Buffer.allocUnsafe(2 + nameEntry.length);
    list.writeUInt16BE(nameEntry.length, 0);
    nameEntry.copy(list, 2);
    extensions.push(_buildExtension(0x0000, list));
  }

  // ── Supported Versions: TLS 1.3 only (0x002b) ───────────────────────────────
  extensions.push(_buildExtension(0x002b, Buffer.from([0x02, 0x03, 0x04])));

  // ── Supported Groups (0x000a) ─────────────────────────────────────────────
  {
    const groups = [GROUP_X25519_MLKEM768, GROUP_X25519]; // PQC önce
    const buf    = Buffer.allocUnsafe(2 + groups.length * 2);
    buf.writeUInt16BE(groups.length * 2, 0);
    groups.forEach((g, i) => buf.writeUInt16BE(g, 2 + i * 2));
    extensions.push(_buildExtension(0x000a, buf));
  }

  // ── Signature Algorithms (0x000d) ────────────────────────────────────────
  {
    const algs = [
      SIG_ECDSA_SECP256R1_SHA256,   // 0x0403
      SIG_RSA_PSS_RSAE_SHA256,      // 0x0804
      0x0401,                        // rsa_pkcs1_sha256
      0x0503,                        // ecdsa_secp384r1_sha384
      SIG_ML_DSA_65,                 // 0x0808
    ];
    const buf = Buffer.allocUnsafe(2 + algs.length * 2);
    buf.writeUInt16BE(algs.length * 2, 0);
    algs.forEach((a, i) => buf.writeUInt16BE(a, 2 + i * 2));
    extensions.push(_buildExtension(0x000d, buf));
  }

  // ── Key Share (0x0033) ──────────────────────────────────────────────────
  // Hybrid format (draft-tls-westerbaan-xyber768d00): mlkemPub(1184) || x25519Pub(32) = 1216
  {
    const x25519Pub   = Buffer.from(this.x25519Key.publicKeyRaw || this.x25519Key.publicKey);
    const mlkemPub    = this.mlkemKey.ek; // 1184 bytes
    const hybridShare = Buffer.concat([mlkemPub, x25519Pub]);

    const hybridEntry = Buffer.allocUnsafe(4 + hybridShare.length);
    hybridEntry.writeUInt16BE(GROUP_X25519_MLKEM768, 0);
    hybridEntry.writeUInt16BE(hybridShare.length, 2);
    hybridShare.copy(hybridEntry, 4);

    const x25519Entry = Buffer.allocUnsafe(4 + x25519Pub.length);
    x25519Entry.writeUInt16BE(GROUP_X25519, 0);
    x25519Entry.writeUInt16BE(x25519Pub.length, 2);
    x25519Pub.copy(x25519Entry, 4);

    const ksList = Buffer.concat([hybridEntry, x25519Entry]);
    const ksBuf  = Buffer.allocUnsafe(2 + ksList.length);
    ksBuf.writeUInt16BE(ksList.length, 0);
    ksList.copy(ksBuf, 2);
    extensions.push(_buildExtension(0x0033, ksBuf));
  }

  // ── ALPN (0x0010) ──────────────────────────────────────────────────────
  {
    const protoList = Buffer.concat(this.alpn.map(p => {
      const pb = Buffer.from(p, 'ascii');
      return Buffer.concat([Buffer.from([pb.length]), pb]);
    }));
    const alpnBuf = Buffer.allocUnsafe(2 + protoList.length);
    alpnBuf.writeUInt16BE(protoList.length, 0);
    protoList.copy(alpnBuf, 2);
    extensions.push(_buildExtension(0x0010, alpnBuf));
  }

  // ── QUIC Transport Parameters (0x0039) ───────────────────────────────────
  if (this.transport === 'quic' && this.transportParams && this.transportParams.length > 0) {
    extensions.push(_buildExtension(QUIC_TP_EXTENSION, this.transportParams));
  }

  // ── PSK (0x0029) — RFC 8446 §4.2.11: MUST be last ───────────────────────
  // Binder zero-filled şimdi; aşağıda in-place patch'lenecek
  let pskHashLen = 0;
  if (this._sessionTicket) {
    const { ticket, psk, cipherSuite, ageAdd, iat } = this._sessionTicket;

    // Ticket'ın cipher suite'ini restore et (binder hash'i için)
    if (cipherSuite && SUITE_INFO[cipherSuite]) this._applyCipherSuite(cipherSuite);
    pskHashLen = this.hashLen;

    // obfuscated_ticket_age = (now - iat + ageAdd) mod 2^32
    const obfAge = ((Date.now() - iat + ageAdd) & 0xffffffff) >>> 0;

    const idEntry = Buffer.allocUnsafe(2 + ticket.length + 4);
    idEntry.writeUInt16BE(ticket.length, 0);
    ticket.copy(idEntry, 2);
    idEntry.writeUInt32BE(obfAge, 2 + ticket.length);

    const idList = Buffer.allocUnsafe(2 + idEntry.length);
    idList.writeUInt16BE(idEntry.length, 0);
    idEntry.copy(idList, 2);

    // Binder list: list_len(2) + binder_len(1) + zeros(hashLen)
    // Binder = HMAC placeholder; gerçek değer aşağıda patch'leniyor
    const binderList = Buffer.alloc(2 + 1 + pskHashLen);
    binderList.writeUInt16BE(1 + pskHashLen, 0);
    binderList[2] = pskHashLen;

    extensions.push(_buildExtension(0x0029, Buffer.concat([idList, binderList])));

    // _deriveHandshakeKeys() bunu kullanarak earlySecret üretecek
    this.resumptionPsk = psk;
  }

  // ── ClientHello Body ────────────────────────────────────────────────────
  const ciphersBuf = Buffer.allocUnsafe(2 + this.allowedCiphers.length * 2);
  ciphersBuf.writeUInt16BE(this.allowedCiphers.length * 2, 0);
  this.allowedCiphers.forEach((c, i) => ciphersBuf.writeUInt16BE(c, 2 + i * 2));

  const extsBuf    = Buffer.concat(extensions);
  const extLenBuf  = Buffer.allocUnsafe(2);
  extLenBuf.writeUInt16BE(extsBuf.length, 0);

  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),           // legacy_version
    this.clientRandom,                    // 32 bytes
    Buffer.from([this.clientSessionId.length]),
    this.clientSessionId,
    ciphersBuf,
    Buffer.from([0x01, 0x00]),           // compression_methods: [null]
    extLenBuf,
    extsBuf,
  ]);

  const chMsg = _wrapHandshake(TLS_HANDSHAKE.CLIENT_HELLO, body);

  // ── PSK Binder Computation (RFC 8446 §4.2.11.2) ──────────────────────────
  // Truncate = chMsg HARIÇ son (2 + 1 + hashLen) byte (binder_list)
  // Çünkü: HMAC(finished_key, Hash(ClientHello_without_binders))
  if (this._sessionTicket && pskHashLen > 0) {
    const binderListOctets = 2 + 1 + pskHashLen; // list_len + binder_len + binder
    const truncated        = chMsg.subarray(0, chMsg.length - binderListOctets);

    // early_secret = HKDF-Extract(0^hashLen, PSK)
    const psk         = this._sessionTicket.psk;
    const earlySecret = hkdfExtract(this.hashAlgo, Buffer.alloc(pskHashLen), psk);

    // binder_key = HKDF-Expand-Label(early_secret, "res binder", Hash(""), hashLen)
    const binderKey   = hkdfExpandLabel(this.hashAlgo, earlySecret, 'res binder', this._getEmptyHash(), pskHashLen);
    const finishedKey = hkdfExpandLabel(this.hashAlgo, binderKey, 'finished', Buffer.alloc(0), pskHashLen);

    // Transcript-Hash(truncated_ClientHello)
    const hashFn  = this.hashAlgo === 'sha384' ? sha384 : sha256;
    const thValue = hashFn(truncated);
    const binder  = hmac(this.hashAlgo, finishedKey, thValue);

    // In-place patch: son pskHashLen byte = binder
    binder.copy(chMsg, chMsg.length - pskHashLen);

    log.info(`${this.roleLog} [PSK] Binder computed (${this.hashAlgo.toUpperCase()}, ${pskHashLen}B)`);
  }

  this._addToTranscript(chMsg);

  log.info(`${this.roleLog} [STATE] ClientHello generated (${chMsg.length}B)`);
  log.debug(`${this.roleLog} [KS] Hybrid X25519+MLKEM768 (${1184+32}B) + X25519 (32B)`);

  return { level: ENCRYPTION_LEVEL.INITIAL, data: chMsg };
}

  _parseKeyShare(data, isServerResponse) {
    if (!isServerResponse) {
      const listLen = data.readUInt16BE(0);
      let off       = 2;
      const end     = 2 + listLen;
      const shares  = new Map();

      while (off + 4 <= end) {
        const group  = data.readUInt16BE(off); off += 2;
        const keyLen = data.readUInt16BE(off); off += 2;
        shares.set(group, data.subarray(off, off + keyLen));
        off += keyLen;
      }

      if (shares.has(GROUP_X25519_MLKEM768)) {
        const ks = shares.get(GROUP_X25519_MLKEM768);
        this.negotiatedGroup = GROUP_X25519_MLKEM768;
        this.peerPublicKey   = ks;
        log.info(`${this.roleLog} [KEY_EXCHANGE] PQS active: FIPS 203 Hybrid (0x11EC) select`);
      }

      if (!this.negotiatedGroup && shares.has(PQC_GROUP_ALT)) {
        const ks = shares.get(PQC_GROUP_ALT);
        this.negotiatedGroup = PQC_GROUP_ALT;
        this.peerPublicKey   = ks;
        log.info(`${this.roleLog} [KEY_EXCHANGE] PQS active (draft): X25519Kyber768 (0xfe30) select`);
      }

      if (!this.negotiatedGroup && shares.has(GROUP_X25519)) {
        if (this.pqcPolicy === 'required') {
          throw Object.assign(new Error('PQC was mandated, but the client did not present a PQC key'), { alertCode: TLS_ALERTS.HANDSHAKE_FAILURE });
        }
        this.negotiatedGroup = GROUP_X25519;
        this.peerPublicKey   = shares.get(GROUP_X25519);
        log.warn(`${this.roleLog} [KEY_EXCHANGE] PQS passive: Reverting to the classic X25519 fallback algorithm`);
      }

      if (!this.negotiatedGroup) {
        throw Object.assign(new Error('No supported common key exchange group was found'), { alertCode: TLS_ALERTS.HANDSHAKE_FAILURE });
      }
    } else {
      this.negotiatedGroup = data.readUInt16BE(0);
      this.peerPublicKey   = data.subarray(4);
    }
  }

  _addToTranscript(msg) { this.transcriptMessages.push(Buffer.from(msg)); }
  
  _getTranscriptHash() {
    const hash = this.hashAlgo === 'sha384' ? sha384 : sha256;
    return hash(Buffer.concat(this.transcriptMessages));
  }
  
  _getTranscriptHashBeforeLast() {
    const hash = this.hashAlgo === 'sha384' ? sha384 : sha256;
    return hash(Buffer.concat(this.transcriptMessages.slice(0, -1)));
  }

  _sendAlert(level, desc) {
    log.warn(`${this.roleLog} [TLS_ALERT] Bağlantı Kesiliyor. Level=${level}, Desc=${desc}`);
    const alertBuf = Buffer.from([level, desc]);

    if (this.transport === 'tcp' && this.onHandshakeData) {
      this.onHandshakeData(21, alertBuf, this.state === 'CONNECTED' || this.state === 'WAIT_CLIENT_FINISHED');
    }

    this.emit('tlsAlert', { level, desc, quicErrorCode: 0x0100 + desc });
  }

  _fatalError(err, alertDesc = TLS_ALERTS.HANDSHAKE_FAILURE) {
    log.error(`${this.roleLog} [TLS_FATAL] Durum Kesilmesi:`, err.message);
    this._sendAlert(2, alertDesc);
    
    if (this.transport === 'tcp' && this.onError) this.onError(err);
    this.emit('tlsError', err);
  }
}

module.exports = { TLS, TLS_HANDSHAKE, ENCRYPTION_LEVEL, TLS_ALERTS };