'use strict';

const { Server } = require('./src/server/server');
const { QuicConnection, Http2Connection, CONN_STATE } = require('./src/connection/connection');
const { QuicStream, Http2Stream,  STREAM_STATE } = require('./src/stream/stream');
const { RecoveryState, PN_SPACE } = require('./src/recovery/recovery');
const { TLS } = require('./src/crypto/tls');
const { CertificateValidator } = require('./src/crypto/cert-validator');
const { PathValidator, ConnectionIdManager, PATH_STATE } = require('./src/connection/migration');
const constants = require('./src/constants');
const Crypto = require('./src/crypto/crypto');
const zeroRtt = require('./src/crypto/zero-rtt');
const packetCodec = require('./src/packet/codec');
const frameCodec = require('./src/frame/codec');
const { encodeTransportParams, decodeTransportParams } = require('./src/transport/params');
const { decodeVarInt, encodeVarInt, varIntLength } = require('./src/transport/varint');

// HTTP/3
const {
  H3Connection, H3Request, H3_FRAME, H3_SETTINGS, H3_ERROR, buildH3Settings,
} = require('./src/h3/http3');
// HTTP/2
const { 
  H2Connection, H2Request, H2_FRAME, H2_SETTINGS, H2_ERROR, buildH2Settings 
} = require('./src/h2/http2');
const { QpackEncoder, QpackDecoder, STATIC_TABLE: QPACK_STATIC_TABLE, DynamicTable: QPACK_DYNAMIC_TABLE } = require('./src/h3/qpack');
const { HpackEncoder, HpackDecoder, STATIC_TABLE: HPACK_STATIC_TABLE, DynamicTable: HPACK_DYNAMIC_TABLE } = require('./src/h2/hpack');

// Observability + 0-RTT policy + early data classifier
const metrics = require('./src/utils/metrics');
const earlyDataPolicy = require('./src/crypto/early-data-policy');

// Router
const { Router } = require('./src/server/router');

// WebTransport
const {
  WebTransportSession,
  WebTransportServer,
  WebTransportClient,
  WT_STATE,
} = require('./src/webtransport/webtransport');

const {
   ServerPush
} = require('./src/push/server-push');

// Gateway (H3 + H2 + H1 unified listener)
const { Http2FallbackGateway } = require('./src/gateway/gateway');

// Logger
const { createLogger, LOG_LEVEL } = require('./src/utils/logger');

module.exports = {
  // High-level API
  Server,
  //QuicServer,
  QuicConnection,
  QuicStream,

  //Http2Server,
  Http2Connection,
  Http2Stream,

  // HTTP/3
  H3Connection,
  H3Request,
  H3_FRAME,
  H3_SETTINGS,
  H3_ERROR,
  buildH3Settings,

  H2Connection,
  H2Request,
  H2_FRAME,
  H2_SETTINGS,
  H2_ERROR,
  buildH2Settings,

  // QPACK
  QpackEncoder,
  QpackDecoder,

  // HPACK
  HpackEncoder,
  HpackDecoder,

  // Router
  Router,

  // WebTransport
  WebTransportSession,
  WebTransportServer,
  WebTransportClient,
  WT_STATE,

  // Push
  ServerPush,

  Http2FallbackGateway,

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
  TLS,
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
  crypto: Crypto,
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
