'use strict';

const { QuicServer } = require('./server/server');
const { QuicClient } = require('./client/client');
const { QuicConnection, CONN_STATE } = require('./connection/connection');
const { QuicStream, STREAM_STATE } = require('./stream/stream');
const { RecoveryState, PN_SPACE } = require('./recovery/recovery');
const { TLSEngine } = require('./crypto/tls-engine');
const { CertificateValidator } = require('./crypto/cert-validator');
const { PathValidator, ConnectionIdManager, PATH_STATE } = require('./connection/migration');
const constants = require('./constants');
const quicCrypto = require('./crypto/quic-crypto');
const chacha20 = require('./crypto/chacha20');
const zeroRtt = require('./crypto/zero-rtt');
const packetCodec = require('./packet/codec');
const frameCodec = require('./frame/codec');
const { encodeTransportParams, decodeTransportParams } = require('./transport/params');
const { decodeVarInt, encodeVarInt, varIntLength } = require('./transport/varint');

// HTTP/3
const {
  H3Connection, H3Request, H3_FRAME, H3_SETTINGS, H3_ERROR, buildH3Settings,
} = require('./h3/http3');
const { QpackEncoder, QpackDecoder, STATIC_TABLE, DynamicTable } = require('./h3/qpack');

// Observability + 0-RTT policy + early data classifier
const metrics = require('./utils/metrics');
const earlyDataPolicy = require('./crypto/early-data-policy');

// Router
const { Router } = require('./server/router');

// High-level HTTP client
const { Http3Client } = require('./client/http3-client');

// WebTransport
const {
  WebTransportSession,
  WebTransportServer,
  WebTransportClient,
  WT_STATE,
} = require('./webtransport/webtransport');

// Gateway (H3 + H2 + H1 unified listener)
const { Http2FallbackGateway } = require('./gateway/gateway');
const { H2StreamAdapter, Http1RequestAdapter } = require('./gateway/h2-adapter');

// Logger
const { createLogger, LOG_LEVEL } = require('./utils/logger');

module.exports = {
  // High-level API
  QuicServer,
  QuicClient,
  QuicConnection,
  QuicStream,

  // HTTP/3
  H3Connection,
  H3Request,
  H3_FRAME,
  H3_SETTINGS,
  H3_ERROR,
  buildH3Settings,

  // QPACK
  QpackEncoder,
  QpackDecoder,

  // Router
  Router,

  // High-level HTTP client
  Http3Client,

  // WebTransport
  WebTransportSession,
  WebTransportServer,
  WebTransportClient,
  WT_STATE,

  // Gateway / H2 fallback
  Http2FallbackGateway,
  H2StreamAdapter,
  Http1RequestAdapter,

  // Certificate Validation
  CertificateValidator,

  // Migration
  PathValidator,
  ConnectionIdManager,
  PATH_STATE,

  // 0-RTT
  SessionTicket: zeroRtt.SessionTicket,
  SessionTicketStore: zeroRtt.SessionTicketStore,

  // Support
  RecoveryState,
  PN_SPACE,
  TLSEngine,
  CONN_STATE,
  STREAM_STATE,

  // Logging
  createLogger,
  LOG_LEVEL,

  // Observability
  metrics,
  Metrics: metrics.Metrics,

  // 0-RTT policy
  earlyDataPolicy,
  ReplayCache: earlyDataPolicy.ReplayCache,
  composeEarlyDataPolicy: earlyDataPolicy.composePolicy,
  isSafeEarlyDataRequest: earlyDataPolicy.isSafeEarlyDataRequest,

  // Low-level
  constants,
  crypto: quicCrypto,
  chacha20,
  zeroRtt,
  packet: packetCodec,
  frame: frameCodec,
  transport: {
    encodeTransportParams,
    decodeTransportParams,
    decodeVarInt,
    encodeVarInt,
    varIntLength,
  },
};
