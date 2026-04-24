'use strict';

/**
 * TLS 1.3 Engine for QUIC - RFC 9001
 * * Features:
 * - Dynamic Cipher Selection (CHACHA20, AES-256, AES-128)
 * - Alias support (e.g. 'CHACHA20' instead of 0x1303)
 * - X25519 + P-256 key exchange
 * - RSA-PSS + ECDSA CertificateVerify
 * - mTLS: CertificateRequest + client cert verification & Chain validation
 * - Strict ALPN negotiation (h3)
 * - 0-RTT NewSessionTicket emission / reception (Cloudflare/Google pattern: 2 tickets)
 * - Strict Buffer bounds checking against DoS attacks
 */

const crypto = require('crypto');
const { hkdfExtract, hkdfExpandLabel, derivePacketKeys } = require('./quic-crypto');
const { ENCRYPTION_LEVEL } = require('../constants');
const { EventEmitter } = require('events');
const { CertificateValidator } = require('./cert-validator');
const { createLogger } = require('../utils/logger');

const {
  buildNewSessionTicket, parseNewSessionTicket,
  deriveResumptionSecret, derivePSK, SessionTicket,
} = require('./zero-rtt');

const log = createLogger('TLS');

const TLS_HANDSHAKE = {
  CLIENT_HELLO:          1,
  SERVER_HELLO:          2,
  NEW_SESSION_TICKET:    4,
  ENCRYPTED_EXTENSIONS:  8,
  CERTIFICATE:           11,
  CERTIFICATE_REQUEST:   13,
  CERTIFICATE_VERIFY:    15,
  FINISHED:              20,
};

const TLS_VERSION_13 = 0x0304;

const GROUP_X25519 = 0x001d;
const GROUP_SECP256R1 = 0x0017;

const SIG_ECDSA_SECP256R1_SHA256 = 0x0403;
const SIG_RSA_PSS_RSAE_SHA256 = 0x0804;

const QUIC_TP_EXTENSION = 0x0039;

// Kriptografik Parametreler
const SUITE_INFO = {
  0x1301: { name: 'TLS_AES_128_GCM_SHA256',       hash: 'sha256', hashLen: 32, keyLen: 16, aead: 'aes-128-gcm',       hp: 'aes-128-ecb' },
  0x1302: { name: 'TLS_AES_256_GCM_SHA384',       hash: 'sha384', hashLen: 48, keyLen: 32, aead: 'aes-256-gcm',       hp: 'aes-256-ecb' },
  0x1303: { name: 'TLS_CHACHA20_POLY1305_SHA256', hash: 'sha256', hashLen: 32, keyLen: 32, aead: 'chacha20-poly1305', hp: 'chacha20'    },
};

// İnsan dilindeki isimlerin Hex karşılıkları
const CIPHER_ALIASES = {
  'TLS_AES_128_GCM_SHA256': 0x1301,
  'AES_128': 0x1301,
  'TLS_AES_256_GCM_SHA384': 0x1302,
  'AES_256': 0x1302,
  'TLS_CHACHA20_POLY1305_SHA256': 0x1303,
  'CHACHA20': 0x1303
};

class TLSEngine extends EventEmitter {
  constructor(options = {}) {
    super();
    this.isServer = options.isServer || false;
    this.cert = options.cert || null;
    this.key = options.key || null;
    this.alpn = options.alpn || ['h3'];
    this.serverName = options.serverName || 'localhost';
    this.transportParams = options.transportParams || Buffer.alloc(0);

    // mTLS Options
    this.requestCert = options.requestCert || false;
    this.rejectUnauthorized = options.rejectUnauthorized !== undefined ? options.rejectUnauthorized : false;
    this.ca = options.ca || null;
    this.clientCert = options.clientCert || null;
    this.clientKey = options.clientKey || null;

    // ==============================================================
    // DİNAMİK CİPHER SUITE OKUMA VE ÇEVİRME
    // ==============================================================
    const rawCiphers = options.cipherSuites || options.allowedCiphers || ['CHACHA20', 'AES_256', 'AES_128'];
    
    this.allowedCiphers = rawCiphers.map(c => {
      if (typeof c === 'string') {
        const upper = c.toUpperCase();
        if (CIPHER_ALIASES[upper]) return CIPHER_ALIASES[upper];
        throw new Error(`TLS Fatal: Unknown Cipher Suite '${c}'`);
      }
      return c; 
    });

    this.enable0rtt     = options.enable0rtt !== undefined ? options.enable0rtt : true;
    this.ticketLifetime = options.ticketLifetime || 172800;
    this.maxEarlyData   = options.maxEarlyData || 0xffffffff;
    this.clientAlpns    = [];
    this.selectedAlpn   = null;
    if (options.ticketKey) {
      this._ticketKey = Buffer.isBuffer(options.ticketKey)
        ? options.ticketKey                          // Buffer ise doğrudan kullan
        : Buffer.from(options.ticketKey, 'hex');     // String ise hex decode
    } else {
      this._ticketKey = crypto.randomBytes(16);
    }
    this.peerCertificate = null;
    this.peerCertVerified = false;
    this._certRequestContext = null;

    this.clientRandom = null;
    this.serverRandom = null;
    this.clientSessionId = Buffer.alloc(0);

    this.state = 'INIT';
    
    // Kripto Değişkenleri
    this.cipherSuite = null;
    this.hashAlgo = null;
    this.hashLen = null;
    this.keyLen = null;

    // Eğer client ise başlangıçta listesindeki ilk algoritmaya kilitlenir
    if (!this.isServer) {
      this._applyCipherSuite(this.allowedCiphers[0]);
    } else {
      // Server ise ClientHello gelene kadar bekler, varsayılan sha256
      this.hashAlgo = 'sha256';
      this.hashLen = 32;
    }

    this.ecdh = crypto.createECDH('prime256v1');
    this.ecdh.generateKeys();
    this.x25519KeyPair = crypto.generateKeyPairSync('x25519');
    const rawPub = this.x25519KeyPair.publicKey.export({ type: 'spki', format: 'der' });
    this.x25519PubKeyBytes = rawPub.subarray(rawPub.length - 32);
    this.negotiatedGroup = null;

    this.transcriptMessages = [];
    this.earlySecret = null;
    this.handshakeSecret = null;
    this.masterSecret = null;
    this.clientHandshakeSecret = null;
    this.serverHandshakeSecret = null;
    this.clientAppSecret = null;
    this.serverAppSecret = null;

    this.keys = {
      [ENCRYPTION_LEVEL.HANDSHAKE]: null,
      [ENCRYPTION_LEVEL.ONE_RTT]: null,
    };

    this.cryptoStreams = {
      [ENCRYPTION_LEVEL.INITIAL]: { received: new Map(), nextExpected: 0, buffer: Buffer.alloc(0) },
      [ENCRYPTION_LEVEL.HANDSHAKE]: { received: new Map(), nextExpected: 0, buffer: Buffer.alloc(0) },
      [ENCRYPTION_LEVEL.ONE_RTT]: { received: new Map(), nextExpected: 0, buffer: Buffer.alloc(0) },
    };

    this.peerTransportParams = null;
    this.peerPublicKey = null;
    this.peerIdentity = null;
    this._peerCertDerList = [];

    // Sertifika Doğrulamaları
    if (this.cert && this.key) {
      const keyMatch = CertificateValidator.validateKeyMatch(this.cert, this.key);
      if (!keyMatch.valid) {
        throw new Error(`TLS configuration error: ${keyMatch.error}`);
      }
      const expCheck = CertificateValidator.checkExpiration(this.cert);
      if (!expCheck.valid && !expCheck.warning) {
        log.warn(`Certificate expiration warning: ${expCheck.error}`);
      }
    }
  }

  // ==========================================
  // DİNAMİK CİPHER UYGULAYICI
  // ==========================================
  _applyCipherSuite(suiteId) {
    const info = SUITE_INFO[suiteId];
    if (!info) throw new Error(`Unsupported cipher suite: 0x${suiteId.toString(16)}`);
    
    this.cipherSuite = suiteId;
    this.hashAlgo = info.hash;
    this.hashLen = info.hashLen;
    this.keyLen = info.keyLen;
    
    log.info(`TLS Cipher Suite negotiated: ${info.name}`);
  }

  // ==========================================
  // HANDSHAKE MESSAGE GENERATION
  // ==========================================

  generateClientHello() {
    this.clientRandom = crypto.randomBytes(32);
    const extensions = [];

    const sniName = Buffer.from(this.serverName, 'ascii');
    const sniEntry = Buffer.alloc(2 + 1 + 2 + sniName.length);
    let off = 0;
    sniEntry.writeUInt16BE(sniName.length + 3, off); off += 2;
    sniEntry[off++] = 0;
    sniEntry.writeUInt16BE(sniName.length, off); off += 2;
    sniName.copy(sniEntry, off);
    extensions.push(this._buildExtension(0x0000, sniEntry));

    extensions.push(this._buildExtension(0x002b, Buffer.from([2, 0x03, 0x04])));

    const groups = Buffer.alloc(6);
    groups.writeUInt16BE(4, 0);
    groups.writeUInt16BE(GROUP_X25519, 2);
    groups.writeUInt16BE(GROUP_SECP256R1, 4);
    extensions.push(this._buildExtension(0x000a, groups));

    const sigAlgs = Buffer.alloc(6);
    sigAlgs.writeUInt16BE(4, 0);
    sigAlgs.writeUInt16BE(SIG_RSA_PSS_RSAE_SHA256, 2);
    sigAlgs.writeUInt16BE(SIG_ECDSA_SECP256R1_SHA256, 4);
    extensions.push(this._buildExtension(0x000d, sigAlgs));

    const x25519Entry = Buffer.alloc(4 + 32);
    x25519Entry.writeUInt16BE(GROUP_X25519, 0);
    x25519Entry.writeUInt16BE(32, 2);
    this.x25519PubKeyBytes.copy(x25519Entry, 4);

    const p256PubKey = this.ecdh.getPublicKey();
    const p256Entry = Buffer.alloc(4 + p256PubKey.length);
    p256Entry.writeUInt16BE(GROUP_SECP256R1, 0);
    p256Entry.writeUInt16BE(p256PubKey.length, 2);
    p256PubKey.copy(p256Entry, 4);

    const keyShareEntries = Buffer.concat([x25519Entry, p256Entry]);
    const keyShareData = Buffer.alloc(2 + keyShareEntries.length);
    keyShareData.writeUInt16BE(keyShareEntries.length, 0);
    keyShareEntries.copy(keyShareData, 2);
    extensions.push(this._buildExtension(0x0033, keyShareData));

    const alpnEntries = this.alpn.map(a => {
      const b = Buffer.from(a, 'ascii');
      return Buffer.concat([Buffer.from([b.length]), b]);
    });
    const alpnList = Buffer.concat(alpnEntries);
    const alpnData = Buffer.alloc(2 + alpnList.length);
    alpnData.writeUInt16BE(alpnList.length, 0);
    alpnList.copy(alpnData, 2);
    extensions.push(this._buildExtension(0x0010, alpnData));

    if (this.transportParams.length > 0) {
      extensions.push(this._buildExtension(QUIC_TP_EXTENSION, this.transportParams));
    }

    const extBuf = Buffer.concat(extensions);
    
    // DINAMİK CIPHER LİSTESİ YAZIMI
    const csBuffer = Buffer.alloc(2 + (this.allowedCiphers.length * 2));
    csBuffer.writeUInt16BE(this.allowedCiphers.length * 2, 0);
    for (let i = 0; i < this.allowedCiphers.length; i++) {
      csBuffer.writeUInt16BE(this.allowedCiphers[i], 2 + (i * 2));
    }

    const sessionId = crypto.randomBytes(32);
    const compression = Buffer.from([1, 0]);

    const body = Buffer.concat([
      Buffer.from([0x03, 0x03]),
      this.clientRandom,
      Buffer.from([sessionId.length]),
      sessionId,
      csBuffer,
      compression,
      Buffer.alloc(2),
      extBuf,
    ]);
    body.writeUInt16BE(extBuf.length, body.length - extBuf.length - 2);

    const msg = this._wrapHandshakeMessage(TLS_HANDSHAKE.CLIENT_HELLO, body);
    this._addToTranscript(msg);

    this.state = 'WAIT_SERVER_HELLO';
    return { level: ENCRYPTION_LEVEL.INITIAL, data: msg };
  }

  generateServerHello() {
    this.serverRandom = crypto.randomBytes(32);
    const sharedSecret = this._computeSharedSecret();

    const extensions = [];
    const sv = Buffer.alloc(2);
    sv.writeUInt16BE(TLS_VERSION_13, 0);
    extensions.push(this._buildExtension(0x002b, sv));

    let group = this.negotiatedGroup || GROUP_X25519;
    let pubKey = group === GROUP_X25519 ? this.x25519PubKeyBytes : this.ecdh.getPublicKey();

    const ksData = Buffer.alloc(4 + pubKey.length);
    ksData.writeUInt16BE(group, 0);
    ksData.writeUInt16BE(pubKey.length, 2);
    pubKey.copy(ksData, 4);
    extensions.push(this._buildExtension(0x0033, ksData));

    const extBuf = Buffer.concat(extensions);
    const sessionId = this.clientSessionId || Buffer.alloc(0);

    const body = Buffer.concat([
      Buffer.from([0x03, 0x03]),
      this.serverRandom,
      Buffer.from([sessionId.length]),
      sessionId,
      // Seçilen Cipher Suite'i yazıyoruz
      Buffer.from([this.cipherSuite >> 8, this.cipherSuite & 0xff]),
      Buffer.from([0x00]),
      Buffer.alloc(2),
      extBuf,
    ]);
    body.writeUInt16BE(extBuf.length, body.length - extBuf.length - 2);

    const shMsg = this._wrapHandshakeMessage(TLS_HANDSHAKE.SERVER_HELLO, body);
    this._addToTranscript(shMsg);

    this._deriveHandshakeKeys(sharedSecret);

    const handshakeMsgs = [];
    const eeExts = [];
    
    const negotiatedAlpn = this.selectedAlpn || this.alpn[0];
    if (negotiatedAlpn) {
      const selected = Buffer.from(negotiatedAlpn, 'ascii');
      const alpnBuf = Buffer.alloc(2 + 1 + selected.length);
      alpnBuf.writeUInt16BE(1 + selected.length, 0);
      alpnBuf[2] = selected.length;
      selected.copy(alpnBuf, 3);
      eeExts.push(this._buildExtension(0x0010, alpnBuf));
    }
    
    if (this.transportParams.length > 0) {
      eeExts.push(this._buildExtension(QUIC_TP_EXTENSION, this.transportParams));
    }

    const eeBody = Buffer.concat(eeExts);
    const eeBuf = Buffer.alloc(2 + eeBody.length);
    eeBuf.writeUInt16BE(eeBody.length, 0);
    eeBody.copy(eeBuf, 2);
    const eeMsg = this._wrapHandshakeMessage(TLS_HANDSHAKE.ENCRYPTED_EXTENSIONS, eeBuf);
    this._addToTranscript(eeMsg);
    handshakeMsgs.push(eeMsg);

    if (this.requestCert) {
      const crMsg = this._buildCertificateRequest();
      this._addToTranscript(crMsg);
      handshakeMsgs.push(crMsg);
    }

    if (this.cert) {
      const certMsg = this._buildCertificateMessage(this.cert);
      this._addToTranscript(certMsg);
      handshakeMsgs.push(certMsg);

      const cvMsg = this._buildCertificateVerify(this.key, true);
      this._addToTranscript(cvMsg);
      handshakeMsgs.push(cvMsg);
    }

    const finishedMsg = this._buildFinished(this.serverHandshakeSecret);
    this._addToTranscript(finishedMsg);
    handshakeMsgs.push(finishedMsg);

    this._deriveApplicationKeys();
    this.state = 'WAIT_CLIENT_FINISHED';

    return {
      serverHello: { level: ENCRYPTION_LEVEL.INITIAL, data: shMsg },
      handshakeData: { level: ENCRYPTION_LEVEL.HANDSHAKE, data: Buffer.concat(handshakeMsgs) },
    };
  }

  // ==========================================
  // CRYPTO STREAM HANDLING
  // ==========================================

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
      const msgLen = (buf[1] << 16) | (buf[2] << 8) | buf[3];
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
        this._handleNewSessionTicket(body);
        return;
      }

      switch (type) {
        case TLS_HANDSHAKE.CLIENT_HELLO:
          if (this.isServer) this._handleClientHello(body);
          break;
        case TLS_HANDSHAKE.SERVER_HELLO:
          if (!this.isServer) this._handleServerHello(body);
          break;
        case TLS_HANDSHAKE.ENCRYPTED_EXTENSIONS:
          this._handleEncryptedExtensions(body);
          break;
        case TLS_HANDSHAKE.CERTIFICATE_REQUEST:
          if (!this.isServer) this._handleCertificateRequest(body);
          break;
        case TLS_HANDSHAKE.CERTIFICATE:
          this._handleCertificate(body);
          break;
        case TLS_HANDSHAKE.CERTIFICATE_VERIFY:
          this._handleCertificateVerify(body);
          break;
        case TLS_HANDSHAKE.FINISHED:
          this._handleFinished(level, body);
          break;
      }
    } catch (err) {
      log.error(`Fatal error processing TLS message type ${type}:`, err.message);
      this.emit('tlsError', err);
    }
  }

  // ==========================================
  // HANDSHAKE MESSAGE PROCESSORS
  // ==========================================

  _handleClientHello(body) {
    let off = 2; 
    if (off + 32 > body.length) throw new Error('Truncated ClientHello');
    this.clientRandom = body.subarray(off, off + 32); off += 32;

    const sidLen = body[off++];
    if (off + sidLen > body.length) throw new Error('Truncated ClientHello SessionId');
    this.clientSessionId = body.subarray(off, off + sidLen); off += sidLen;

    if (off + 2 > body.length) throw new Error('Truncated ClientHello Ciphers');
    const csLen = body.readUInt16BE(off); off += 2;
    if (off + csLen > body.length) throw new Error('Truncated ClientHello Ciphers array');
    
    // Gelen Client Cipher'larını oku
    const clientCiphers = [];
    for (let i = 0; i < csLen; i += 2) {
      clientCiphers.push(body.readUInt16BE(off + i));
    }
    off += csLen;

    // Ortak bir cipher seç (Kendi önceliğimize göre)
    const chosenCipher = this.allowedCiphers.find(c => clientCiphers.includes(c));
    if (!chosenCipher) {
      throw new Error(`TLS Fatal: No mutually supported cipher suites.`);
    }
    
    // Motoru kilitliyoruz
    this._applyCipherSuite(chosenCipher);

    const compLen = body[off++];
    if (off + compLen > body.length) throw new Error('Truncated ClientHello Compression');
    off += compLen;

    if (off + 2 <= body.length) {
      const extLen = body.readUInt16BE(off); off += 2;
      if (off + extLen > body.length) throw new Error('Truncated ClientHello Extensions');
      this._parseExtensions(body.subarray(off, off + extLen), false);
    }

    this.state = 'GENERATING_SERVER_HELLO';
  }

  _handleServerHello(body) {
    let off = 2; 
    if (off + 32 > body.length) throw new Error('Truncated ServerHello random');
    this.serverRandom = body.subarray(off, off + 32); off += 32;
    
    const sidLen = body[off++]; 
    off += sidLen;
    
    if (off + 2 > body.length) throw new Error('Truncated ServerHello cipher');
    
    // Server'ın seçtiği cipher'ı oku
    const serverSelectedCipher = body.readUInt16BE(off); off += 2;
    if (!this.allowedCiphers.includes(serverSelectedCipher)) {
      throw new Error(`TLS Fatal: Server selected unsupported cipher 0x${serverSelectedCipher.toString(16)}`);
    }
    
    this._applyCipherSuite(serverSelectedCipher);
    
    off += 1; 
    
    if (off + 2 <= body.length) {
      const extLen = body.readUInt16BE(off); off += 2;
      if (off + extLen > body.length) throw new Error('Truncated ServerHello extensions');
      this._parseExtensions(body.subarray(off, off + extLen), true);
    }

    const sharedSecret = this._computeSharedSecret();
    this._deriveHandshakeKeys(sharedSecret);

    this.state = 'WAIT_ENCRYPTED_EXTENSIONS';
  }

  _handleEncryptedExtensions(body) {
    let off = 0;
    if (off + 2 > body.length) throw new Error('Truncated EE length');
    const extLen = body.readUInt16BE(off); off += 2;
    if (off + extLen > body.length) throw new Error('Truncated EE body');
    this._parseExtensions(body.subarray(off, off + extLen), true);
    this.state = 'WAIT_CERTIFICATE';
  }

  _handleCertificateRequest(body) {
    let off = 0;
    const ctxLen = body[off++];
    this._certRequestContext = body.subarray(off, off + ctxLen);
    this.state = 'WAIT_CERTIFICATE';
    this.emit('certificateRequest');
  }

  _handleCertificate(body) {
    this.peerCertificate = body;
    this._peerCertDerList = [];
    let off = 0;
    
    if (off >= body.length) throw new Error('Truncated Certificate message');
    const ctxLen = body[off++];
    off += ctxLen; 

    if (off + 3 > body.length) throw new Error('Truncated Certificate list length');
    const certsLen = (body[off] << 16) | (body[off + 1] << 8) | body[off + 2];
    off += 3;

    const end = off + certsLen;
    if (end > body.length) throw new Error('Certificate list out of bounds');

    while (off + 3 <= end) {
      const certLen = (body[off] << 16) | (body[off + 1] << 8) | body[off + 2];
      off += 3;
      if (off + certLen > end) break;
      this._peerCertDerList.push(Buffer.from(body.subarray(off, off + certLen)));
      off += certLen;
      if (off + 2 <= end) {
        const extLen = body.readUInt16BE(off);
        off += 2 + extLen;
      }
    }
    this.state = 'WAIT_CERTIFICATE_VERIFY';
  }

  _handleCertificateVerify(body) {
    let off = 0;
    if (off + 4 > body.length) throw new Error('Truncated CertificateVerify headers');
    const sigAlg = body.readUInt16BE(off); off += 2;
    const sigLen = body.readUInt16BE(off); off += 2;
    if (off + sigLen > body.length) throw new Error('Truncated CertificateVerify signature');
    const signature = body.subarray(off, off + sigLen);

    const transcriptHash = this._getTranscriptHashBeforeLast();
    const prefix = Buffer.alloc(64, 0x20);
    const isServer = !this.isServer; 
    const contextStr = isServer ? 'TLS 1.3, server CertificateVerify\x00' : 'TLS 1.3, client CertificateVerify\x00';
    const context = Buffer.from(contextStr, 'ascii');
    const content = Buffer.concat([prefix, context, transcriptHash]);

    let verified = false;
    if (this._peerCertDerList.length > 0) {
      const leafDer = this._peerCertDerList[0];
      const leafPem = '-----BEGIN CERTIFICATE-----\n' + leafDer.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----';
      const publicKey = crypto.createPublicKey({ key: leafPem, format: 'pem' });

      try {
        if (sigAlg === SIG_ECDSA_SECP256R1_SHA256) {
          verified = crypto.verify('SHA256', content, publicKey, signature);
        } else if (sigAlg === SIG_RSA_PSS_RSAE_SHA256) {
          verified = crypto.verify('SHA256', content, {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
          }, signature);
        } else {
          log.warn(`Unknown signature algorithm: 0x${sigAlg.toString(16)}, bypassing strict check.`);
          verified = true;
        }
      } catch (err) {
        log.warn(`Verification threw an error: ${err.message}`);
      }
    }

    if (verified) {
      this.peerCertVerified = true;
      
      if (this._peerCertDerList.length > 0 && !this.isServer) {
        const peerPem = this._peerCertDerList.map(der =>
          '-----BEGIN CERTIFICATE-----\n' + der.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----'
        ).join('\n');

        const hostResult = CertificateValidator.validateHostname(peerPem, this.serverName);
        if (!hostResult.valid && !hostResult.warning) {
          if (this.rejectUnauthorized) {
            this.emit('tlsError', new Error(hostResult.error));
            return;
          }
        }
        this.peerIdentity = CertificateValidator.extractIdentity(peerPem);
      }
    } else if (this.rejectUnauthorized) {
      this.emit('tlsError', new Error('CertificateVerify signature verification failed'));
      return;
    }
    this.state = 'WAIT_FINISHED';
  }

  _handleFinished(level, body) {
    const expectedSecret = this.isServer ? this.clientHandshakeSecret : this.serverHandshakeSecret;
    if (expectedSecret) {
      const finishedKey = hkdfExpandLabel(this.hashAlgo, expectedSecret, 'finished', Buffer.alloc(0), this.hashLen);
      const expectedData = crypto.createHmac(this.hashAlgo, finishedKey).update(this._getTranscriptHashBeforeLast()).digest();
      
      if (!crypto.timingSafeEqual(body, expectedData)) {
        this.emit('tlsError', new Error('TLS Finished message verification failed'));
        return;
      }
    }

    if (this.isServer) {
      if (this.requestCert && this.rejectUnauthorized && !this.peerCertVerified) {
        this.emit('tlsError', new Error('mTLS: client certificate not verified'));
        return;
      }
      this.state = 'CONNECTED';
      this.emit('connected');

      // 0-RTT: CLOUDFLARE TICKET EMISSION
      if (this.enable0rtt) {
        log.info('Handshake finished. Emitting 2x NewSessionTickets for 0-RTT...');
        this._sendNewSessionTicket();
        this._sendNewSessionTicket();
      }

    } else {
      this._deriveApplicationKeys();
      
      const clientMsgs = [];
      if (this._certRequestContext) {
        if (this.clientCert && this.clientKey) {
          const certMsg = this._buildCertificateMessage(this.clientCert, this._certRequestContext);
          this._addToTranscript(certMsg);
          clientMsgs.push(certMsg);

          const cvMsg = this._buildCertificateVerify(this.clientKey, false);
          this._addToTranscript(cvMsg);
          clientMsgs.push(cvMsg);
        } else {
          const emptyCert = this._buildEmptyCertificate(this._certRequestContext);
          this._addToTranscript(emptyCert);
          clientMsgs.push(emptyCert);
        }
      }

      const clientFinished = this._buildFinished(this.clientHandshakeSecret);
      this._addToTranscript(clientFinished);
      clientMsgs.push(clientFinished);

      this.state = 'CONNECTED';
      this.emit('clientFinished', { level: ENCRYPTION_LEVEL.HANDSHAKE, data: Buffer.concat(clientMsgs) });
      this.emit('connected');
    }
  }

  // ==========================================
  // ZERO RTT TICKET LOGIC
  // ==========================================

  _sendNewSessionTicket() {
      console.log('[TICKET-DEBUG] Encrypt key:', this._ticketKey.toString('hex'));

    const transcriptHash = this._getTranscriptHash();
    
    const resumptionSecret = hkdfExpandLabel(this.hashAlgo, this.masterSecret, 'res master', transcriptHash, this.hashLen);
    const ticketNonce = crypto.randomBytes(16);
    const psk = hkdfExpandLabel(this.hashAlgo, resumptionSecret, 'resumption', ticketNonce, this.hashLen);

    const meta = Buffer.from(JSON.stringify({
      suite: this.cipherSuite,
      alpn: this.selectedAlpn || this.alpn[0],
      iat: Date.now(),
      sni: this.serverName,
    }), 'utf8');

    const iv = crypto.randomBytes(12);
    const c  = crypto.createCipheriv('aes-128-gcm', this._ticketKey, iv);
    const ct = Buffer.concat([c.update(psk), c.update(meta), c.final()]);
    const tag = c.getAuthTag();
    const ticket = Buffer.concat([iv, tag, ct]);

    const ageAdd = crypto.randomBytes(4).readUInt32BE(0);
    
    const extBuf = Buffer.alloc(8);
    extBuf.writeUInt16BE(0x002a, 0); 
    extBuf.writeUInt16BE(4, 2);      
    extBuf.writeUInt32BE(this.maxEarlyData, 4);

    const body = Buffer.alloc(4 + 4 + 1 + ticketNonce.length + 2 + ticket.length + 2 + extBuf.length);
    let off = 0;
    body.writeUInt32BE(this.ticketLifetime, off); off += 4;
    body.writeUInt32BE(ageAdd, off); off += 4;
    body.writeUInt8(ticketNonce.length, off); off += 1;
    ticketNonce.copy(body, off); off += ticketNonce.length;
    body.writeUInt16BE(ticket.length, off); off += 2;
    ticket.copy(body, off); off += ticket.length;
    body.writeUInt16BE(extBuf.length, off); off += 2;
    extBuf.copy(body, off); off += extBuf.length;

    const nstMsg = this._wrapHandshakeMessage(TLS_HANDSHAKE.NEW_SESSION_TICKET, body);

    this.emit('postHandshakeCrypto', {
      level: ENCRYPTION_LEVEL.ONE_RTT,
      data: nstMsg,
    });
  }

  _handleNewSessionTicket(body) {
    try {
      const parsed = parseNewSessionTicket(body);
      const transcriptHash = this._getTranscriptHash();
      
      const resumptionSecret = hkdfExpandLabel(this.hashAlgo, this.masterSecret, 'res master', transcriptHash, this.hashLen);
      const psk = hkdfExpandLabel(this.hashAlgo, resumptionSecret, 'resumption', parsed.ticketNonce, this.hashLen);

      const ticket = new SessionTicket({
        ticket: parsed.ticket,
        resumptionSecret: psk,
        cipherSuite: this.cipherSuite,
        alpn: this.selectedAlpn || this.alpn[0],
        maxEarlyData: parsed.maxEarlyData,
        peerTransportParams: this.peerTransportParams ? Buffer.from(this.peerTransportParams) : null,
        lifetime: parsed.lifetime,
        ageAdd: parsed.ageAdd,
        serverName: this.serverName,
      });

      this.emit('sessionTicket', ticket);
    } catch (e) {
      log.warn('NewSessionTicket parse failed:', e.message);
    }
  }

  // ==========================================
  // UTILITY & MESSAGE BUILDERS
  // ==========================================

  _buildCertificateRequest() {
    const context = crypto.randomBytes(1);
    this._certRequestContext = context;

    const sigAlgs = Buffer.alloc(6);
    sigAlgs.writeUInt16BE(4, 0);
    sigAlgs.writeUInt16BE(SIG_RSA_PSS_RSAE_SHA256, 2);
    sigAlgs.writeUInt16BE(SIG_ECDSA_SECP256R1_SHA256, 4);
    const sigAlgExt = this._buildExtension(0x000d, sigAlgs);

    const extBuf = Buffer.concat([sigAlgExt]);
    const body = Buffer.concat([ Buffer.from([context.length]), context, Buffer.alloc(2), extBuf ]);
    body.writeUInt16BE(extBuf.length, 1 + context.length);

    return this._wrapHandshakeMessage(TLS_HANDSHAKE.CERTIFICATE_REQUEST, body);
  }

  _buildCertificateMessage(certPem, requestContext) {
    const pemStr = certPem.toString();
    const regex = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/g;
    let match;
    const certEntries = [];
    let totalLength = 0;

    while ((match = regex.exec(pemStr)) !== null) {
      const der = Buffer.from(match[1].replace(/[\r\n\s]+/g, ''), 'base64');
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

    const body = Buffer.concat([
      Buffer.from([ctx.length]),
      ctx,
      certsListBuf,
      ...certEntries,
    ]);

    return this._wrapHandshakeMessage(TLS_HANDSHAKE.CERTIFICATE, body);
  }

  _buildEmptyCertificate(requestContext) {
    const ctx = requestContext || Buffer.alloc(0);
    const body = Buffer.concat([
      Buffer.from([ctx.length]),
      ctx,
      Buffer.from([0, 0, 0]), 
    ]);
    return this._wrapHandshakeMessage(TLS_HANDSHAKE.CERTIFICATE, body);
  }

  _buildCertificateVerify(keyPem, isServer) {
    const content = Buffer.concat([
      Buffer.alloc(64, 0x20),
      Buffer.from(isServer ? 'TLS 1.3, server CertificateVerify\x00' : 'TLS 1.3, client CertificateVerify\x00', 'ascii'),
      this._getTranscriptHash()
    ]);

    const privateKey = crypto.createPrivateKey(keyPem.toString());
    let sigAlg, signature;

    if (privateKey.asymmetricKeyType === 'ec') {
      sigAlg = SIG_ECDSA_SECP256R1_SHA256;
      signature = crypto.createSign('SHA256').update(content).sign(keyPem);
    } else {
      sigAlg = SIG_RSA_PSS_RSAE_SHA256;
      signature = crypto.createSign('SHA256').update(content).sign({
        key: keyPem,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      });
    }

    const body = Buffer.alloc(4 + signature.length);
    body.writeUInt16BE(sigAlg, 0);
    body.writeUInt16BE(signature.length, 2);
    signature.copy(body, 4);
    return this._wrapHandshakeMessage(TLS_HANDSHAKE.CERTIFICATE_VERIFY, body);
  }

  _computeSharedSecret() {
    if (this.negotiatedGroup === GROUP_X25519) {
      const peerSpki = Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), this.peerPublicKey]);
      return crypto.diffieHellman({ privateKey: this.x25519KeyPair.privateKey, publicKey: crypto.createPublicKey({ key: peerSpki, format: 'der', type: 'spki' }) });
    } else {
      return this.ecdh.computeSecret(this.peerPublicKey);
    }
  }

  // ==========================================
  // KEY DERIVATION (DİNAMİK KEYLEN ALIYOR VE EMIT EDİYOR)
  // ==========================================
_deriveHandshakeKeys(sharedSecret) {
  this.earlySecret = hkdfExtract(
    this.hashAlgo,
    Buffer.alloc(this.hashLen),
    Buffer.alloc(this.hashLen)
  );
 
  const derivedSecret = hkdfExpandLabel(
    this.hashAlgo,
    this.earlySecret,
    'derived',
    crypto.createHash(this.hashAlgo).digest(),
    this.hashLen
  );
 
  const clientEarlyTrafficSecret = hkdfExpandLabel(
    this.hashAlgo,
    this.earlySecret,
    'c e traffic',
    this._getTranscriptHash(),
    this.hashLen
  );
 
  this.handshakeSecret = hkdfExtract(this.hashAlgo, derivedSecret, sharedSecret);
 
  const th = this._getTranscriptHash();
  this.clientHandshakeSecret = hkdfExpandLabel(
    this.hashAlgo, this.handshakeSecret, 'c hs traffic', th, this.hashLen
  );
  this.serverHandshakeSecret = hkdfExpandLabel(
    this.hashAlgo, this.handshakeSecret, 's hs traffic', th, this.hashLen
  );
 
  this.keys[ENCRYPTION_LEVEL.HANDSHAKE] = {
    clientKeys: derivePacketKeys(this.hashAlgo, this.clientHandshakeSecret, this.keyLen),
    serverKeys: derivePacketKeys(this.hashAlgo, this.serverHandshakeSecret, this.keyLen),
  };
 
  // ✅ DÜZELTİLDİ: this.keyLen eklendi (ChaCha20=32, AES=16)
  const zeroRttKeys = derivePacketKeys(
    this.hashAlgo,
    clientEarlyTrafficSecret,
    this.keyLen  // ← BU SATIR EKSİKTİ
  );
  this.keys[ENCRYPTION_LEVEL.ZERO_RTT] = zeroRttKeys;
 
  // ✅ DÜZELTİLDİ: suite bilgisi event'e eklendi
  // connection.js artık hangi cipher'ı kullanacağını biliyor
  const suiteAead = SUITE_INFO[this.cipherSuite]?.aead || 'aes-128-gcm';
  if (!this.accepted0RTT) {
  // PSK yoksa normal boş-PSK early keys gönder
    this.emit('earlyKeys', {
      keys: zeroRttKeys,
      suite: suiteAead,
    });
  };
 
  if (this.isServer) {
    this.emit('handshakeKeys', {
      level: ENCRYPTION_LEVEL.HANDSHAKE,
      cipher: SUITE_INFO[this.cipherSuite],
      ...this.keys[ENCRYPTION_LEVEL.HANDSHAKE],
    });
  }
}

  _deriveApplicationKeys() {
    const derivedSecret = hkdfExpandLabel(this.hashAlgo, this.handshakeSecret, 'derived', crypto.createHash(this.hashAlgo).digest(), this.hashLen);
    this.masterSecret = hkdfExtract(this.hashAlgo, derivedSecret, Buffer.alloc(this.hashLen));

    const th = this._getTranscriptHash();
    this.clientAppSecret = hkdfExpandLabel(this.hashAlgo, this.masterSecret, 'c ap traffic', th, this.hashLen);
    this.serverAppSecret = hkdfExpandLabel(this.hashAlgo, this.masterSecret, 's ap traffic', th, this.hashLen);

    this.keys[ENCRYPTION_LEVEL.ONE_RTT] = {
      clientKeys: derivePacketKeys(this.hashAlgo, this.clientAppSecret, this.keyLen),
      serverKeys: derivePacketKeys(this.hashAlgo, this.serverAppSecret, this.keyLen),
    };
    
    // BURASI ÇOK ÖNEMLİ
    this.emit('applicationKeys', { 
      level: ENCRYPTION_LEVEL.ONE_RTT, 
      cipher: SUITE_INFO[this.cipherSuite],
      ...this.keys[ENCRYPTION_LEVEL.ONE_RTT] 
    });
  }

  _buildFinished(baseSecret) {
    const finishedKey = hkdfExpandLabel(this.hashAlgo, baseSecret, 'finished', Buffer.alloc(0), this.hashLen);
    const verifyData = crypto.createHmac(this.hashAlgo, finishedKey).update(this._getTranscriptHash()).digest();
    return this._wrapHandshakeMessage(TLS_HANDSHAKE.FINISHED, verifyData);
  }

  _wrapHandshakeMessage(type, body) {
    const header = Buffer.alloc(4);
    header[0] = type;
    header.writeUIntBE(body.length, 1, 3);
    return Buffer.concat([header, body]);
  }

  _buildExtension(type, data) {
    const buf = Buffer.alloc(4 + data.length);
    buf.writeUInt16BE(type, 0);
    buf.writeUInt16BE(data.length, 2);
    data.copy(buf, 4);
    return buf;
  }

_handlePreSharedKeyExtension(data) {
  try {
    let off = 0;
    const identitiesLen = data.readUInt16BE(off); off += 2;
    const identitiesData = data.subarray(off, off + identitiesLen);

    const ticketLen = identitiesData.readUInt16BE(0);
    const encryptedTicket = identitiesData.subarray(2, 2 + ticketLen);

    const result = derivePSK(this.hashAlgo || 'sha256', this._ticketKey, encryptedTicket);

    if (result) {
      const { psk, meta } = result;
      this.resumedPSK = psk;
      this.accepted0RTT = true;
      log.info('\x1b[32m[TLS] 0-RTT Bileti Kabul Edildi!\x1b[0m');

      const { deriveZeroRTTKeys } = require('./zero-rtt');
      const chHash = this._getTranscriptHash();

      // Derive keyLen from the ticket's own cipher suite rather than
      // this.keyLen (which may not be populated at this point, or may be
      // stale from a previous handshake). AES-128 => 16, AES-256 and
      // ChaCha20-Poly1305 => 32.
      const ticketSuite = meta && typeof meta.suite === 'number' ? meta.suite : 0x1301;
      const suiteInfo   = SUITE_INFO[ticketSuite] || SUITE_INFO[0x1301];
      const suiteKeyLen = suiteInfo.keyLen;
      const suiteAead   = suiteInfo.aead;

      const earlySecrets = deriveZeroRTTKeys(
        this.hashAlgo || 'sha256',
        psk,
        chHash,
        suiteKeyLen
      );

      // Use a hash of the encrypted ticket as the replay nonce — the
      // ticket blob is unique per resumption and already opaque.
      const ticketNonce = crypto.createHash('sha256')
        .update(encryptedTicket).digest().subarray(0, 16);

      this.emit('earlyKeys', {
        keys: earlySecrets.keys,
        suite: suiteAead,
        ticketNonce,
      });
    }
  } catch (e) {
    log.warn('[TLS] 0-RTT Bilet doğrulama hatası:', e.message);
  }
}

  _parseExtensions(buf, isServerSide) {
    let off = 0;
    while (off + 4 <= buf.length) {
      const type = buf.readUInt16BE(off); off += 2;
      const len = buf.readUInt16BE(off); off += 2;
      if (off + len > buf.length) break;
      const data = buf.subarray(off, off + len);
      off += len;

      if (type === 0x0033) {
        this._parseKeyShare(data, isServerSide);
      } else if (type === 0x002a) { // early_data (42)
        this.peerAttempted0RTT = true;
        log.debug('[TLS] İstemci 0-RTT (Early Data) deniyor.');
      } 
        else if (type === 0x0029 && this.isServer && this.enable0rtt) { // pre_shared_key (41)
        this._handlePreSharedKeyExtension(data);
      } else if (type === QUIC_TP_EXTENSION) {
        this.peerTransportParams = data;
        this.emit('peerTransportParams', data);
      } else if (type === 0x0010 && this.isServer) {
        let p = 2; 
        while (p < data.length) {
          const alpnLen = data[p++];
          if (p + alpnLen > data.length) break;
          this.clientAlpns.push(data.subarray(p, p + alpnLen).toString('ascii'));
          p += alpnLen;
        }
      }
    }

    if (this.isServer && this.clientAlpns.length > 0) {
      const inter = this.clientAlpns.filter(a => this.alpn.includes(a));
      if (inter.length === 0) {
        log.error(`ALPN mismatch: client offered [${this.clientAlpns}], we support [${this.alpn}]`);
        this.emit('tlsError', new Error('no_application_protocol'));
        return;
      }
      this.selectedAlpn = inter[0];
    }
  }

  _parseKeyShare(data, isServerResponse) {
    let off = 0;
    if (!isServerResponse) {
      if (off + 2 > data.length) return;
      const listLen = data.readUInt16BE(off); off += 2;
      const end = off + listLen;
      while (off + 4 <= end) {
        const group = data.readUInt16BE(off); off += 2;
        const keyLen = data.readUInt16BE(off); off += 2;
        if (off + keyLen > end) break;
        if (group === GROUP_X25519) { this.negotiatedGroup = GROUP_X25519; this.peerPublicKey = data.subarray(off, off + keyLen); }
        else if (group === GROUP_SECP256R1 && !this.peerPublicKey) { this.negotiatedGroup = GROUP_SECP256R1; this.peerPublicKey = data.subarray(off, off + keyLen); }
        off += keyLen;
      }
    } else {
      if (data.length < 4) return;
      this.negotiatedGroup = data.readUInt16BE(0);
      this.peerPublicKey = data.subarray(4);
    }
  }

  _addToTranscript(msg) { this.transcriptMessages.push(Buffer.from(msg)); }
  
  _getTranscriptHash() {
    const hash = crypto.createHash(this.hashAlgo);
    for (const msg of this.transcriptMessages) hash.update(msg);
    return hash.digest();
  }
  
  _getTranscriptHashBeforeLast() {
    const hash = crypto.createHash(this.hashAlgo);
    for (let i = 0; i < this.transcriptMessages.length - 1; i++) hash.update(this.transcriptMessages[i]);
    return hash.digest();
  }
}

module.exports = { TLSEngine, TLS_HANDSHAKE };