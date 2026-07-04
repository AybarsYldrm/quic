'use strict';

const { TRANSPORT_PARAM, DEFAULT_PARAMS } = require('../constants');
const { decodeVarInt, encodeVarInt } = require('../transport/varint');

function encodeTransportParams(params, isServer = false) {
  const entries = [];

  function addParam(id, value) {
    const idBuf = encodeVarInt(id);
    if (Buffer.isBuffer(value)) {
      entries.push(idBuf, encodeVarInt(value.length), value);
    } else {
      const valBuf = encodeVarInt(value);
      entries.push(idBuf, encodeVarInt(valBuf.length), valBuf);
    }
  }

  if (params.originalDestinationConnectionId !== undefined && isServer) {
    addParam(TRANSPORT_PARAM.ORIGINAL_DESTINATION_CONNECTION_ID, params.originalDestinationConnectionId);
  }

  if (params.maxIdleTimeout !== undefined) {
    addParam(TRANSPORT_PARAM.MAX_IDLE_TIMEOUT, params.maxIdleTimeout);
  }

  if (params.statelessResetToken !== undefined && isServer) {
    addParam(TRANSPORT_PARAM.STATELESS_RESET_TOKEN, params.statelessResetToken);
  }

  if (params.maxUdpPayloadSize !== undefined) {
    addParam(TRANSPORT_PARAM.MAX_UDP_PAYLOAD_SIZE, params.maxUdpPayloadSize);
  }

  if (params.initialMaxData !== undefined) {
    addParam(TRANSPORT_PARAM.INITIAL_MAX_DATA, params.initialMaxData);
  }

  if (params.initialMaxStreamDataBidiLocal !== undefined) {
    addParam(TRANSPORT_PARAM.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, params.initialMaxStreamDataBidiLocal);
  }

  if (params.initialMaxStreamDataBidiRemote !== undefined) {
    addParam(TRANSPORT_PARAM.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, params.initialMaxStreamDataBidiRemote);
  }

  if (params.initialMaxStreamDataUni !== undefined) {
    addParam(TRANSPORT_PARAM.INITIAL_MAX_STREAM_DATA_UNI, params.initialMaxStreamDataUni);
  }

  if (params.initialMaxStreamsBidi !== undefined) {
    addParam(TRANSPORT_PARAM.INITIAL_MAX_STREAMS_BIDI, params.initialMaxStreamsBidi);
  }

  if (params.initialMaxStreamsUni !== undefined) {
    addParam(TRANSPORT_PARAM.INITIAL_MAX_STREAMS_UNI, params.initialMaxStreamsUni);
  }

  if (params.ackDelayExponent !== undefined) {
    addParam(TRANSPORT_PARAM.ACK_DELAY_EXPONENT, params.ackDelayExponent);
  }

  if (params.maxAckDelay !== undefined) {
    addParam(TRANSPORT_PARAM.MAX_ACK_DELAY, params.maxAckDelay);
  }

  if (params.disableActiveMigration) {
    const idBuf = encodeVarInt(TRANSPORT_PARAM.DISABLE_ACTIVE_MIGRATION);
    entries.push(idBuf, encodeVarInt(0)); // zero-length value
  }

  if (params.activeConnectionIdLimit !== undefined) {
    addParam(TRANSPORT_PARAM.ACTIVE_CONNECTION_ID_LIMIT, params.activeConnectionIdLimit);
  }

  if (params.initialSourceConnectionId !== undefined) {
    addParam(TRANSPORT_PARAM.INITIAL_SOURCE_CONNECTION_ID, params.initialSourceConnectionId);
  }

  if (params.retrySourceConnectionId !== undefined && isServer) {
    addParam(TRANSPORT_PARAM.RETRY_SOURCE_CONNECTION_ID, params.retrySourceConnectionId);
  }

  if (params.maxDatagramFrameSize !== undefined) {
    addParam(0x0020, params.maxDatagramFrameSize);
  }

  return Buffer.concat(entries);
}

function decodeTransportParams(buf) {
  const params = {};
  let offset = 0;

  while (offset < buf.length) {
    const { value: paramId, length: idLen } = decodeVarInt(buf, offset);
    offset += idLen;

    const { value: paramLen, length: pLen } = decodeVarInt(buf, offset);
    offset += pLen;

    const paramData = buf.subarray(offset, offset + paramLen);
    offset += paramLen;

    switch (paramId) {
      case TRANSPORT_PARAM.ORIGINAL_DESTINATION_CONNECTION_ID:
        params.originalDestinationConnectionId = Buffer.from(paramData);
        break;
      case TRANSPORT_PARAM.MAX_IDLE_TIMEOUT:
        params.maxIdleTimeout = paramLen > 0 ? decodeVarInt(paramData, 0).value : 0;
        break;
      case TRANSPORT_PARAM.STATELESS_RESET_TOKEN:
        params.statelessResetToken = Buffer.from(paramData);
        break;
      case TRANSPORT_PARAM.MAX_UDP_PAYLOAD_SIZE:
        params.maxUdpPayloadSize = decodeVarInt(paramData, 0).value;
        break;
      case TRANSPORT_PARAM.INITIAL_MAX_DATA:
        params.initialMaxData = decodeVarInt(paramData, 0).value;
        break;
      case TRANSPORT_PARAM.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
        params.initialMaxStreamDataBidiLocal = decodeVarInt(paramData, 0).value;
        break;
      case TRANSPORT_PARAM.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
        params.initialMaxStreamDataBidiRemote = decodeVarInt(paramData, 0).value;
        break;
      case TRANSPORT_PARAM.INITIAL_MAX_STREAM_DATA_UNI:
        params.initialMaxStreamDataUni = decodeVarInt(paramData, 0).value;
        break;
      case TRANSPORT_PARAM.INITIAL_MAX_STREAMS_BIDI:
        params.initialMaxStreamsBidi = decodeVarInt(paramData, 0).value;
        break;
      case TRANSPORT_PARAM.INITIAL_MAX_STREAMS_UNI:
        params.initialMaxStreamsUni = decodeVarInt(paramData, 0).value;
        break;
      case TRANSPORT_PARAM.ACK_DELAY_EXPONENT:
        params.ackDelayExponent = decodeVarInt(paramData, 0).value;
        break;
      case TRANSPORT_PARAM.MAX_ACK_DELAY:
        params.maxAckDelay = decodeVarInt(paramData, 0).value;
        break;
      case TRANSPORT_PARAM.DISABLE_ACTIVE_MIGRATION:
        params.disableActiveMigration = true;
        break;
      case TRANSPORT_PARAM.ACTIVE_CONNECTION_ID_LIMIT:
        params.activeConnectionIdLimit = decodeVarInt(paramData, 0).value;
        break;
      case TRANSPORT_PARAM.INITIAL_SOURCE_CONNECTION_ID:
        params.initialSourceConnectionId = Buffer.from(paramData);
        break;
      case TRANSPORT_PARAM.RETRY_SOURCE_CONNECTION_ID:
        params.retrySourceConnectionId = Buffer.from(paramData);
        break;
      case 0x0020:
        params.maxDatagramFrameSize = decodeVarInt(paramData, 0).value;
        break;
      default:
        // Unknown param — store raw
        params[`unknown_0x${paramId.toString(16)}`] = Buffer.from(paramData);
        break;
    }
  }

  return params;
}

module.exports = { encodeTransportParams, decodeTransportParams };