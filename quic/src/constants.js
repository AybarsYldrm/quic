'use strict';

// QUIC Version - RFC 9000 Section 15
const QUIC_VERSION_1 = 0x00000001;
const QUIC_VERSION_2 = 0x6b3343cf; // RFC 9369

// Packet types - RFC 9000 Section 17.2
const PACKET_TYPE = {
  INITIAL:   0x00,
  ZERO_RTT:  0x01,
  HANDSHAKE: 0x02,
  RETRY:     0x03,
};

// Frame types - RFC 9000 Section 19
const FRAME_TYPE = {
  PADDING:                0x00,
  PING:                   0x01,
  ACK:                    0x02,
  ACK_ECN:               0x03,
  RESET_STREAM:           0x04,
  STOP_SENDING:           0x05,
  CRYPTO:                 0x06,
  NEW_TOKEN:              0x07,
  STREAM:                 0x08, // 0x08-0x0f
  MAX_DATA:               0x10,
  MAX_STREAM_DATA:        0x11,
  MAX_STREAMS_BIDI:       0x12,
  MAX_STREAMS_UNI:        0x13,
  DATA_BLOCKED:           0x14,
  STREAM_DATA_BLOCKED:    0x15,
  STREAMS_BLOCKED_BIDI:   0x16,
  STREAMS_BLOCKED_UNI:    0x17,
  NEW_CONNECTION_ID:       0x18,
  RETIRE_CONNECTION_ID:    0x19,
  PATH_CHALLENGE:          0x1a,
  PATH_RESPONSE:           0x1b,
  CONNECTION_CLOSE:        0x1c,
  CONNECTION_CLOSE_APP:    0x1d,
  HANDSHAKE_DONE:          0x1e,
  // DATAGRAM frames - RFC 9221
  DATAGRAM:                0x30,
  DATAGRAM_WITH_LEN:       0x31,
};

// Transport Error Codes - RFC 9000 Section 20
const TRANSPORT_ERROR = {
  NO_ERROR:                  0x00,
  INTERNAL_ERROR:            0x01,
  CONNECTION_REFUSED:        0x02,
  FLOW_CONTROL_ERROR:        0x03,
  STREAM_LIMIT_ERROR:        0x04,
  STREAM_STATE_ERROR:        0x05,
  FINAL_SIZE_ERROR:          0x06,
  FRAME_ENCODING_ERROR:      0x07,
  TRANSPORT_PARAMETER_ERROR: 0x08,
  CONNECTION_ID_LIMIT_ERROR: 0x09,
  PROTOCOL_VIOLATION:        0x0a,
  INVALID_TOKEN:             0x0b,
  APPLICATION_ERROR:         0x0c,
  CRYPTO_BUFFER_EXCEEDED:    0x0d,
  KEY_UPDATE_ERROR:          0x0e,
  AEAD_LIMIT_REACHED:        0x0f,
  NO_VIABLE_PATH:            0x10,
  CRYPTO_ERROR:              0x0100, // 0x0100-0x01ff
};

// Transport Parameters - RFC 9000 Section 18
const TRANSPORT_PARAM = {
  ORIGINAL_DESTINATION_CONNECTION_ID: 0x00,
  MAX_IDLE_TIMEOUT:                   0x01,
  STATELESS_RESET_TOKEN:              0x02,
  MAX_UDP_PAYLOAD_SIZE:               0x03,
  INITIAL_MAX_DATA:                   0x04,
  INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: 0x05,
  INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:0x06,
  INITIAL_MAX_STREAM_DATA_UNI:        0x07,
  INITIAL_MAX_STREAMS_BIDI:           0x08,
  INITIAL_MAX_STREAMS_UNI:            0x09,
  ACK_DELAY_EXPONENT:                 0x0a,
  MAX_ACK_DELAY:                      0x0b,
  DISABLE_ACTIVE_MIGRATION:           0x0c,
  PREFERRED_ADDRESS:                  0x0d,
  ACTIVE_CONNECTION_ID_LIMIT:         0x0e,
  INITIAL_SOURCE_CONNECTION_ID:       0x0f,
  RETRY_SOURCE_CONNECTION_ID:         0x10,
};

// Encryption levels
const ENCRYPTION_LEVEL = {
  INITIAL:   0,
  HANDSHAKE: 1,
  ZERO_RTT:  2,
  ONE_RTT:   3,
};

// Default transport parameter values
const DEFAULT_PARAMS = {
  maxIdleTimeout:                30000,
  maxUdpPayloadSize:             1200,
  initialMaxData:                1048576,      // 1MB
  initialMaxStreamDataBidiLocal: 262144,       // 256KB
  initialMaxStreamDataBidiRemote:262144,
  initialMaxStreamDataUni:       262144,
  initialMaxStreamsBidi:         100,
  initialMaxStreamsUni:           100,
  ackDelayExponent:              3,
  maxAckDelay:                   25,
  activeConnectionIdLimit:       2,
};

// Initial packet size
const MIN_INITIAL_PACKET_SIZE = 1200; // RFC 9000 Section 14
const MAX_CID_LENGTH = 20;
const INITIAL_TOKEN_LIFETIME = 60000; // ms

// AEAD algorithms
const AEAD_AES_128_GCM = 'aes-128-gcm';
const AEAD_AES_256_GCM = 'aes-256-gcm';
const AEAD_CHACHA20_POLY1305 = 'chacha20-poly1305';

// Key sizes
const AEAD_KEY_LENGTH = 16;
const AEAD_IV_LENGTH = 12;
const AEAD_TAG_LENGTH = 16;
const HP_KEY_LENGTH = 16;

// Initial salt for QUIC v1 - RFC 9001 Section 5.2
const INITIAL_SALT_V1 = Buffer.from(
  '38762cf7f55934b34d179ae6a4c80cadccbb7f0a', 'hex'
);

// Initial salt for QUIC v2 - RFC 9369
const INITIAL_SALT_V2 = Buffer.from(
  '0dede3def700a6db819381be6e269dcbf9bd2ed9', 'hex'
);

// Header protection mask
const HP_MASK_LONG = 0x0f;
const HP_MASK_SHORT = 0x1f;

// Retry integrity tag key/nonce - RFC 9001 Section 5.8
const RETRY_KEY_V1 = Buffer.from('be0c690b9f66575a1d766b54e368c84e', 'hex');
const RETRY_NONCE_V1 = Buffer.from('461599d35d632bf2239825bb', 'hex');

module.exports = {
  QUIC_VERSION_1, QUIC_VERSION_2,
  PACKET_TYPE, FRAME_TYPE, TRANSPORT_ERROR, TRANSPORT_PARAM,
  ENCRYPTION_LEVEL, DEFAULT_PARAMS,
  MIN_INITIAL_PACKET_SIZE, MAX_CID_LENGTH, INITIAL_TOKEN_LIFETIME,
  AEAD_AES_128_GCM, AEAD_AES_256_GCM, AEAD_CHACHA20_POLY1305,
  AEAD_KEY_LENGTH, AEAD_IV_LENGTH, AEAD_TAG_LENGTH, HP_KEY_LENGTH,
  INITIAL_SALT_V1, INITIAL_SALT_V2,
  HP_MASK_LONG, HP_MASK_SHORT,
  RETRY_KEY_V1, RETRY_NONCE_V1,
};