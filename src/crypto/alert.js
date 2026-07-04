'use strict';

// TLS 1.3 Alert Protocol (RFC 8446 §6)

const AlertLevel = {
  WARNING: 1,
  FATAL: 2,
};

const AlertDescription = {
  CLOSE_NOTIFY: 0,
  UNEXPECTED_MESSAGE: 10,
  BAD_RECORD_MAC: 20,
  RECORD_OVERFLOW: 22,
  HANDSHAKE_FAILURE: 40,
  BAD_CERTIFICATE: 42,
  UNSUPPORTED_CERTIFICATE: 43,
  CERTIFICATE_REVOKED: 44,
  CERTIFICATE_EXPIRED: 45,
  CERTIFICATE_UNKNOWN: 46,
  ILLEGAL_PARAMETER: 47,
  UNKNOWN_CA: 48,
  ACCESS_DENIED: 49,
  DECODE_ERROR: 50,
  DECRYPT_ERROR: 51,
  PROTOCOL_VERSION: 70,
  INSUFFICIENT_SECURITY: 71,
  INTERNAL_ERROR: 80,
  INAPPROPRIATE_FALLBACK: 86,
  USER_CANCELED: 90,
  MISSING_EXTENSION: 109,
  UNSUPPORTED_EXTENSION: 110,
  UNRECOGNIZED_NAME: 112,
  BAD_CERTIFICATE_STATUS_RESPONSE: 113,
  UNKNOWN_PSK_IDENTITY: 115,
  CERTIFICATE_REQUIRED: 116,
  NO_APPLICATION_PROTOCOL: 120,
};

const DESC_NAMES = Object.fromEntries(
  Object.entries(AlertDescription).map(([k, v]) => [v, k])
);

function createAlert(level, description) {
  return Buffer.from([level, description]);
}

function parseAlert(data) {
  if (data.length < 2) throw new Error('Alert too short');
  return {
    level: data[0],
    description: data[1],
    levelName: data[0] === 1 ? 'WARNING' : 'FATAL',
    descriptionName: DESC_NAMES[data[1]] || `UNKNOWN(${data[1]})`,
  };
}

function isFatal(alert) {
  // In TLS 1.3, all alerts except close_notify and user_canceled are fatal
  return alert.description !== AlertDescription.CLOSE_NOTIFY &&
         alert.description !== AlertDescription.USER_CANCELED;
}

module.exports = {
  AlertLevel,
  AlertDescription,
  createAlert,
  parseAlert,
  isFatal
};