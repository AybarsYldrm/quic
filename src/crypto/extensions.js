'use strict';

// TLS 1.3 Extensions Parser/Builder (RFC 8446 §4.2)
const { BufferReader } = require('../utils/buffer-reader.js');
const { BufferWriter } = require('../utils/buffer-writer.js');

// Extension type IDs
const ExtensionType = {
  SERVER_NAME: 0,               // SNI
  MAX_FRAGMENT_LENGTH: 1,
  STATUS_REQUEST: 5,            // OCSP
  SUPPORTED_GROUPS: 10,
  SIGNATURE_ALGORITHMS: 13,
  USE_SRTP: 14,
  HEARTBEAT: 15,
  ALPN: 16,
  SIGNED_CERT_TIMESTAMP: 18,
  CLIENT_CERT_TYPE: 19,
  SERVER_CERT_TYPE: 20,
  PADDING: 21,
  PRE_SHARED_KEY: 41,
  EARLY_DATA: 42,
  SUPPORTED_VERSIONS: 43,
  COOKIE: 44,
  PSK_KEY_EXCHANGE_MODES: 45,
  CERTIFICATE_AUTHORITIES: 47,
  OID_FILTERS: 48,
  POST_HANDSHAKE_AUTH: 49,
  SIGNATURE_ALGORITHMS_CERT: 50,
  KEY_SHARE: 51,
  QUIC_TRANSPORT_PARAMETERS: 57,
};

// Named groups
const NamedGroup = {
  secp256r1: 0x0017,
  secp384r1: 0x0018,
  secp521r1: 0x0019,
  x25519: 0x001d,
  x448: 0x001e,
};

// Signature algorithms
const SignatureScheme = {
  ecdsa_secp256r1_sha256: 0x0403,
  ecdsa_secp384r1_sha384: 0x0503,
  ecdsa_secp521r1_sha512: 0x0603,
  rsa_pss_rsae_sha256: 0x0804,
  rsa_pss_rsae_sha384: 0x0805,
  rsa_pss_rsae_sha512: 0x0806,
  rsa_pkcs1_sha256: 0x0401,
  rsa_pkcs1_sha384: 0x0501,
  rsa_pkcs1_sha512: 0x0601,
};

// PSK key exchange modes
const PskKeyExchangeMode = {
  PSK_KE: 0,
  PSK_DHE_KE: 1,
};

// ============================================================
// Extension Parsing
// ============================================================
function parseExtensions(data) {
  const reader = new BufferReader(data);
  const extensions = new Map();

  while (!reader.eof) {
    const type = reader.readUInt16();
    const extData = reader.readLenPrefixed16();
    extensions.set(type, parseExtension(type, extData));
  }

  return extensions;
}

function parseExtension(type, data) {
  switch (type) {
    case ExtensionType.SERVER_NAME:
      return parseSNI(data);
    case ExtensionType.SUPPORTED_VERSIONS:
      return parseSupportedVersions(data);
    case ExtensionType.KEY_SHARE:
      return parseKeyShare(data);
    case ExtensionType.SUPPORTED_GROUPS:
      return parseSupportedGroups(data);
    case ExtensionType.SIGNATURE_ALGORITHMS:
      return parseSignatureAlgorithms(data);
    case ExtensionType.ALPN:
      return parseALPN(data);
    case ExtensionType.PSK_KEY_EXCHANGE_MODES:
      return parsePSKModes(data);
    case ExtensionType.PRE_SHARED_KEY:
      return parsePSK(data);
    default:
      return { raw: data };
  }
}

// SNI (Server Name Indication)
function parseSNI(data) {
  const reader = new BufferReader(data);
  const listData = reader.readLenPrefixed16();
  const listReader = new BufferReader(listData);
  const names = [];

  while (!listReader.eof) {
    const nameType = listReader.readUInt8();
    const name = listReader.readLenPrefixed16();
    if (nameType === 0) { // host_name
      names.push(name.toString('ascii'));
    }
  }

  return { serverNames: names, hostname: names[0] || null };
}

// Supported Versions (ClientHello: list, ServerHello: single)
function parseSupportedVersions(data) {
  const reader = new BufferReader(data);
  // ClientHello format: length-prefixed list
  if (data.length > 2) {
    const listLen = reader.readUInt8();
    const versions = [];
    for (let i = 0; i < listLen; i += 2) {
      versions.push(reader.readUInt16());
    }
    return { versions };
  }
  // ServerHello format: single version
  return { version: reader.readUInt16() };
}

// Key Share (ClientHello: list, ServerHello: single)
function parseKeyShare(data) {
  const reader = new BufferReader(data);

  // Try as ClientHello (length-prefixed list)
  if (data.length > 4) {
    try {
      const listData = reader.readLenPrefixed16();
      const listReader = new BufferReader(listData);
      const entries = [];

      while (!listReader.eof) {
        const group = listReader.readUInt16();
        const keyExchange = listReader.readLenPrefixed16();
        entries.push({ group, keyExchange: Buffer.from(keyExchange) });
      }

      return { entries };
    } catch {
      // Fall through to ServerHello format
    }
  }

  // ServerHello format: single entry
  const reader2 = new BufferReader(data);
  const group = reader2.readUInt16();
  const keyExchange = reader2.readLenPrefixed16();
  return { group, keyExchange: Buffer.from(keyExchange) };
}

// Supported Groups
function parseSupportedGroups(data) {
  const reader = new BufferReader(data);
  const listData = reader.readLenPrefixed16();
  const listReader = new BufferReader(listData);
  const groups = [];

  while (!listReader.eof) {
    groups.push(listReader.readUInt16());
  }

  return { groups };
}

// Signature Algorithms
function parseSignatureAlgorithms(data) {
  const reader = new BufferReader(data);
  const listData = reader.readLenPrefixed16();
  const listReader = new BufferReader(listData);
  const algorithms = [];

  while (!listReader.eof) {
    algorithms.push(listReader.readUInt16());
  }

  return { algorithms };
}

// ALPN
function parseALPN(data) {
  const reader = new BufferReader(data);
  const listData = reader.readLenPrefixed16();
  const listReader = new BufferReader(listData);
  const protocols = [];

  while (!listReader.eof) {
    const proto = listReader.readLenPrefixed8();
    protocols.push(proto.toString('ascii'));
  }

  return { protocols };
}

// PSK Key Exchange Modes
function parsePSKModes(data) {
  const reader = new BufferReader(data);
  const len = reader.readUInt8();
  const modes = [];
  for (let i = 0; i < len; i++) {
    modes.push(reader.readUInt8());
  }
  return { modes };
}

// Pre-Shared Key (ClientHello)
function parsePSK(data) {
  const reader = new BufferReader(data);
  // Identities
  const identitiesData = reader.readLenPrefixed16();
  const idReader = new BufferReader(identitiesData);
  const identities = [];
  while (!idReader.eof) {
    const identity = idReader.readLenPrefixed16();
    const obfuscatedTicketAge = idReader.readUInt32();
    identities.push({ identity: Buffer.from(identity), obfuscatedTicketAge });
  }
  // Binders
  const bindersData = reader.readLenPrefixed16();
  const bReader = new BufferReader(bindersData);
  const binders = [];
  while (!bReader.eof) {
    binders.push(Buffer.from(bReader.readLenPrefixed8()));
  }
  return { identities, binders };
}

// ============================================================
// Extension Building
// ============================================================
function buildExtension(type, data) {
  const w = new BufferWriter(4 + data.length);
  w.writeUInt16(type);
  w.writeLenPrefixed16(data);
  return w.toBuffer();
}

function buildSNI(hostname) {
  const nameBytes = Buffer.from(hostname, 'ascii');
  const inner = new BufferWriter(32);
  inner.writeUInt8(0); // host_name type
  inner.writeLenPrefixed16(nameBytes);
  const outer = new BufferWriter(32);
  outer.writeLenPrefixed16(inner.toBuffer());
  return buildExtension(ExtensionType.SERVER_NAME, outer.toBuffer());
}

function buildSupportedVersionsServer(version) {
  const data = Buffer.alloc(2);
  data.writeUInt16BE(version);
  return buildExtension(ExtensionType.SUPPORTED_VERSIONS, data);
}

function buildSupportedVersionsClient(versions) {
  const w = new BufferWriter(16);
  w.writeUInt8(versions.length * 2);
  for (const v of versions) w.writeUInt16(v);
  return buildExtension(ExtensionType.SUPPORTED_VERSIONS, w.toBuffer());
}

function buildKeyShareServer(group, publicKey) {
  const w = new BufferWriter(64);
  w.writeUInt16(group);
  w.writeLenPrefixed16(publicKey);
  return buildExtension(ExtensionType.KEY_SHARE, w.toBuffer());
}

function buildKeyShareClient(entries) {
  const inner = new BufferWriter(128);
  for (const { group, keyExchange } of entries) {
    inner.writeUInt16(group);
    inner.writeLenPrefixed16(keyExchange);
  }
  const outer = new BufferWriter(128);
  outer.writeLenPrefixed16(inner.toBuffer());
  return buildExtension(ExtensionType.KEY_SHARE, outer.toBuffer());
}

function buildSupportedGroups(groups) {
  const inner = new BufferWriter(16);
  for (const g of groups) inner.writeUInt16(g);
  const outer = new BufferWriter(16);
  outer.writeLenPrefixed16(inner.toBuffer());
  return buildExtension(ExtensionType.SUPPORTED_GROUPS, outer.toBuffer());
}

function buildSignatureAlgorithms(algorithms) {
  const inner = new BufferWriter(16);
  for (const a of algorithms) inner.writeUInt16(a);
  const outer = new BufferWriter(16);
  outer.writeLenPrefixed16(inner.toBuffer());
  return buildExtension(ExtensionType.SIGNATURE_ALGORITHMS, outer.toBuffer());
}

function buildALPN(protocols) {
  const inner = new BufferWriter(32);
  for (const p of protocols) {
    inner.writeLenPrefixed8(Buffer.from(p, 'ascii'));
  }
  const outer = new BufferWriter(32);
  outer.writeLenPrefixed16(inner.toBuffer());
  return buildExtension(ExtensionType.ALPN, outer.toBuffer());
}

function buildALPNServer(protocol) {
  return buildALPN([protocol]);
}

function buildPSKModes(modes) {
  const w = new BufferWriter(4);
  w.writeUInt8(modes.length);
  for (const m of modes) w.writeUInt8(m);
  return buildExtension(ExtensionType.PSK_KEY_EXCHANGE_MODES, w.toBuffer());
}

module.exports = {
  ExtensionType,
  NamedGroup,
  SignatureScheme,
  PskKeyExchangeMode,
  parseExtensions,
  buildExtension,
  buildSNI,
  buildSupportedVersionsServer,
  buildSupportedVersionsClient,
  buildKeyShareServer,
  buildKeyShareClient,
  buildSupportedGroups,
  buildSignatureAlgorithms,
  buildALPN,
  buildALPNServer,
  buildPSKModes
};