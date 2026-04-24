'use strict';

const { FRAME_TYPE } = require('../constants');
const { decodeVarInt, encodeVarInt, varIntLength } = require('../transport/varint');

// ----- Frame Decoding -----

function decodeFrames(buf) {
  const frames = [];
  let offset = 0;

  while (offset < buf.length) {
    const { value: frameType, length: ftLen } = decodeVarInt(buf, offset);
    offset += ftLen;

    switch (frameType) {
      case FRAME_TYPE.PADDING:
        // Consecutive padding bytes
        while (offset < buf.length && buf[offset] === 0x00) offset++;
        frames.push({ type: FRAME_TYPE.PADDING });
        break;

      case FRAME_TYPE.PING:
        frames.push({ type: FRAME_TYPE.PING });
        break;

      case FRAME_TYPE.ACK:
      case FRAME_TYPE.ACK_ECN: {
        const f = decodeAckFrame(buf, offset, frameType === FRAME_TYPE.ACK_ECN);
        offset = f.offset;
        frames.push(f.frame);
        break;
      }

      case FRAME_TYPE.RESET_STREAM: {
        const f = decodeResetStream(buf, offset);
        offset = f.offset;
        frames.push(f.frame);
        break;
      }

      case FRAME_TYPE.STOP_SENDING: {
        const f = decodeStopSending(buf, offset);
        offset = f.offset;
        frames.push(f.frame);
        break;
      }

      case FRAME_TYPE.CRYPTO: {
        const f = decodeCryptoFrame(buf, offset);
        offset = f.offset;
        frames.push(f.frame);
        break;
      }

      case FRAME_TYPE.NEW_TOKEN: {
        const f = decodeNewToken(buf, offset);
        offset = f.offset;
        frames.push(f.frame);
        break;
      }

      case FRAME_TYPE.MAX_DATA: {
        const { value: maxData, length: l } = decodeVarInt(buf, offset);
        offset += l;
        frames.push({ type: FRAME_TYPE.MAX_DATA, maxData });
        break;
      }

      case FRAME_TYPE.MAX_STREAM_DATA: {
        const { value: streamId, length: l1 } = decodeVarInt(buf, offset); offset += l1;
        const { value: maxData, length: l2 } = decodeVarInt(buf, offset); offset += l2;
        frames.push({ type: FRAME_TYPE.MAX_STREAM_DATA, streamId, maxData });
        break;
      }

      case FRAME_TYPE.MAX_STREAMS_BIDI:
      case FRAME_TYPE.MAX_STREAMS_UNI: {
        const { value: maxStreams, length: l } = decodeVarInt(buf, offset);
        offset += l;
        frames.push({ type: frameType, maxStreams });
        break;
      }

      case FRAME_TYPE.DATA_BLOCKED: {
        const { value: maxData, length: l } = decodeVarInt(buf, offset);
        offset += l;
        frames.push({ type: FRAME_TYPE.DATA_BLOCKED, maxData });
        break;
      }

      case FRAME_TYPE.STREAM_DATA_BLOCKED: {
        const { value: streamId, length: l1 } = decodeVarInt(buf, offset); offset += l1;
        const { value: maxData, length: l2 } = decodeVarInt(buf, offset); offset += l2;
        frames.push({ type: FRAME_TYPE.STREAM_DATA_BLOCKED, streamId, maxData });
        break;
      }

      case FRAME_TYPE.STREAMS_BLOCKED_BIDI:
      case FRAME_TYPE.STREAMS_BLOCKED_UNI: {
        const { value: maxStreams, length: l } = decodeVarInt(buf, offset);
        offset += l;
        frames.push({ type: frameType, maxStreams });
        break;
      }

      case FRAME_TYPE.NEW_CONNECTION_ID: {
        const f = decodeNewConnectionId(buf, offset);
        offset = f.offset;
        frames.push(f.frame);
        break;
      }

      case FRAME_TYPE.RETIRE_CONNECTION_ID: {
        const { value: seqNum, length: l } = decodeVarInt(buf, offset);
        offset += l;
        frames.push({ type: FRAME_TYPE.RETIRE_CONNECTION_ID, sequenceNumber: seqNum });
        break;
      }

      case FRAME_TYPE.PATH_CHALLENGE: {
        const data = buf.subarray(offset, offset + 8);
        offset += 8;
        frames.push({ type: FRAME_TYPE.PATH_CHALLENGE, data });
        break;
      }

      case FRAME_TYPE.PATH_RESPONSE: {
        const data = buf.subarray(offset, offset + 8);
        offset += 8;
        frames.push({ type: FRAME_TYPE.PATH_RESPONSE, data });
        break;
      }

      case FRAME_TYPE.CONNECTION_CLOSE:
      case FRAME_TYPE.CONNECTION_CLOSE_APP: {
        const f = decodeConnectionClose(buf, offset, frameType);
        offset = f.offset;
        frames.push(f.frame);
        break;
      }

      case FRAME_TYPE.HANDSHAKE_DONE:
        frames.push({ type: FRAME_TYPE.HANDSHAKE_DONE });
        break;

      // DATAGRAM frames - RFC 9221
      case FRAME_TYPE.DATAGRAM: {
        // DATAGRAM without length: data extends to end of packet
        const data = buf.subarray(offset);
        offset = buf.length;
        frames.push({ type: FRAME_TYPE.DATAGRAM, data });
        break;
      }

      case FRAME_TYPE.DATAGRAM_WITH_LEN: {
        const { value: dgLen, length: dlLen } = decodeVarInt(buf, offset);
        offset += dlLen;
        const data = buf.subarray(offset, offset + dgLen);
        offset += dgLen;
        frames.push({ type: FRAME_TYPE.DATAGRAM_WITH_LEN, data });
        break;
      }

      default: {
        // STREAM frames: 0x08-0x0f
        if (frameType >= 0x08 && frameType <= 0x0f) {
          const f = decodeStreamFrame(buf, offset, frameType);
          offset = f.offset;
          frames.push(f.frame);
        } else {
          // Unknown frame type - gracefully skip
          // Try to read as varint-length-prefixed (common extension pattern)
          // If that fails, skip the rest of the buffer
          try {
            const { value: unknownLen, length: ulLen } = decodeVarInt(buf, offset);
            offset += ulLen + unknownLen;
          } catch (_) {
            offset = buf.length; // Cannot determine length, skip rest
          }
        }
      }
    }
  }

  return frames;
}

function decodeAckFrame(buf, offset, hasEcn) {
  const { value: largestAck, length: l1 } = decodeVarInt(buf, offset); offset += l1;
  const { value: ackDelay, length: l2 } = decodeVarInt(buf, offset); offset += l2;
  const { value: ackRangeCount, length: l3 } = decodeVarInt(buf, offset); offset += l3;
  const { value: firstAckRange, length: l4 } = decodeVarInt(buf, offset); offset += l4;

  const ranges = [{ start: largestAck - firstAckRange, end: largestAck }];
  let smallest = largestAck - firstAckRange;

  for (let i = 0; i < ackRangeCount; i++) {
    const { value: gap, length: gl } = decodeVarInt(buf, offset); offset += gl;
    const { value: rangeLen, length: rl } = decodeVarInt(buf, offset); offset += rl;
    const rangeEnd = smallest - gap - 2;
    const rangeStart = rangeEnd - rangeLen;
    ranges.push({ start: rangeStart, end: rangeEnd });
    smallest = rangeStart;
  }

  const frame = {
    type: hasEcn ? FRAME_TYPE.ACK_ECN : FRAME_TYPE.ACK,
    largestAck,
    ackDelay,
    ranges,
  };

  if (hasEcn) {
    const { value: ect0, length: e1 } = decodeVarInt(buf, offset); offset += e1;
    const { value: ect1, length: e2 } = decodeVarInt(buf, offset); offset += e2;
    const { value: ecnCe, length: e3 } = decodeVarInt(buf, offset); offset += e3;
    frame.ect0 = ect0;
    frame.ect1 = ect1;
    frame.ecnCe = ecnCe;
  }

  return { frame, offset };
}

function decodeResetStream(buf, offset) {
  const { value: streamId, length: l1 } = decodeVarInt(buf, offset); offset += l1;
  const { value: appErrorCode, length: l2 } = decodeVarInt(buf, offset); offset += l2;
  const { value: finalSize, length: l3 } = decodeVarInt(buf, offset); offset += l3;
  return {
    frame: { type: FRAME_TYPE.RESET_STREAM, streamId, appErrorCode, finalSize },
    offset,
  };
}

function decodeStopSending(buf, offset) {
  const { value: streamId, length: l1 } = decodeVarInt(buf, offset); offset += l1;
  const { value: appErrorCode, length: l2 } = decodeVarInt(buf, offset); offset += l2;
  return {
    frame: { type: FRAME_TYPE.STOP_SENDING, streamId, appErrorCode },
    offset,
  };
}

function decodeCryptoFrame(buf, offset) {
  const { value: cryptoOffset, length: l1 } = decodeVarInt(buf, offset); offset += l1;
  const { value: cryptoLength, length: l2 } = decodeVarInt(buf, offset); offset += l2;
  const data = buf.subarray(offset, offset + cryptoLength);
  offset += cryptoLength;
  return {
    frame: { type: FRAME_TYPE.CRYPTO, offset: cryptoOffset, data },
    offset,
  };
}

function decodeNewToken(buf, offset) {
  const { value: tokenLen, length: l1 } = decodeVarInt(buf, offset); offset += l1;
  const token = buf.subarray(offset, offset + tokenLen);
  offset += tokenLen;
  return {
    frame: { type: FRAME_TYPE.NEW_TOKEN, token },
    offset,
  };
}

function decodeStreamFrame(buf, offset, frameType) {
  const off_bit = (frameType & 0x04) !== 0;
  const len_bit = (frameType & 0x02) !== 0;
  const fin_bit = (frameType & 0x01) !== 0;

  const { value: streamId, length: l1 } = decodeVarInt(buf, offset); offset += l1;

  let streamOffset = 0;
  if (off_bit) {
    const r = decodeVarInt(buf, offset);
    streamOffset = r.value;
    offset += r.length;
  }

  let dataLength;
  if (len_bit) {
    const r = decodeVarInt(buf, offset);
    dataLength = r.value;
    offset += r.length;
  } else {
    dataLength = buf.length - offset;
  }

  const data = buf.subarray(offset, offset + dataLength);
  offset += dataLength;

  return {
    frame: {
      type: FRAME_TYPE.STREAM,
      streamId,
      offset: streamOffset,
      data,
      fin: fin_bit,
    },
    offset,
  };
}

function decodeNewConnectionId(buf, offset) {
  const { value: seqNum, length: l1 } = decodeVarInt(buf, offset); offset += l1;
  const { value: retirePrior, length: l2 } = decodeVarInt(buf, offset); offset += l2;
  const cidLen = buf[offset++];
  const connectionId = buf.subarray(offset, offset + cidLen); offset += cidLen;
  const statelessResetToken = buf.subarray(offset, offset + 16); offset += 16;
  return {
    frame: {
      type: FRAME_TYPE.NEW_CONNECTION_ID,
      sequenceNumber: seqNum,
      retirePriorTo: retirePrior,
      connectionId,
      statelessResetToken,
    },
    offset,
  };
}

function decodeConnectionClose(buf, offset, frameType) {
  const { value: errorCode, length: l1 } = decodeVarInt(buf, offset); offset += l1;

  let triggerFrameType = 0;
  if (frameType === FRAME_TYPE.CONNECTION_CLOSE) {
    const r = decodeVarInt(buf, offset);
    triggerFrameType = r.value;
    offset += r.length;
  }

  const { value: reasonLen, length: l2 } = decodeVarInt(buf, offset); offset += l2;
  const reasonPhrase = buf.subarray(offset, offset + reasonLen).toString('utf8');
  offset += reasonLen;

  return {
    frame: {
      type: frameType,
      errorCode,
      triggerFrameType,
      reasonPhrase,
    },
    offset,
  };
}

// ----- Frame Encoding -----

function encodeFrame(frame) {
  switch (frame.type) {
    case FRAME_TYPE.PADDING:
      return Buffer.alloc(frame.length || 1, 0);

    case FRAME_TYPE.PING:
      return encodeVarInt(FRAME_TYPE.PING);

    case FRAME_TYPE.ACK:
    case FRAME_TYPE.ACK_ECN:
      return encodeAckFrame(frame);

    case FRAME_TYPE.CRYPTO:
      return encodeCryptoFrame(frame);

    case FRAME_TYPE.STREAM:
      return encodeStreamFrame(frame);

    case FRAME_TYPE.MAX_DATA:
      return Buffer.concat([encodeVarInt(FRAME_TYPE.MAX_DATA), encodeVarInt(frame.maxData)]);

    case FRAME_TYPE.MAX_STREAM_DATA:
      return Buffer.concat([
        encodeVarInt(FRAME_TYPE.MAX_STREAM_DATA),
        encodeVarInt(frame.streamId),
        encodeVarInt(frame.maxData),
      ]);

    case FRAME_TYPE.MAX_STREAMS_BIDI:
    case FRAME_TYPE.MAX_STREAMS_UNI:
      return Buffer.concat([encodeVarInt(frame.type), encodeVarInt(frame.maxStreams)]);

    case FRAME_TYPE.DATA_BLOCKED:
      return Buffer.concat([encodeVarInt(FRAME_TYPE.DATA_BLOCKED), encodeVarInt(frame.maxData)]);

    case FRAME_TYPE.STREAM_DATA_BLOCKED:
      return Buffer.concat([
        encodeVarInt(FRAME_TYPE.STREAM_DATA_BLOCKED),
        encodeVarInt(frame.streamId),
        encodeVarInt(frame.maxData),
      ]);

    case FRAME_TYPE.NEW_CONNECTION_ID:
      return encodeNewConnectionId(frame);

    case FRAME_TYPE.RETIRE_CONNECTION_ID:
      return Buffer.concat([
        encodeVarInt(FRAME_TYPE.RETIRE_CONNECTION_ID),
        encodeVarInt(frame.sequenceNumber),
      ]);

    case FRAME_TYPE.PATH_CHALLENGE:
      return Buffer.concat([encodeVarInt(FRAME_TYPE.PATH_CHALLENGE), frame.data]);

    case FRAME_TYPE.PATH_RESPONSE:
      return Buffer.concat([encodeVarInt(FRAME_TYPE.PATH_RESPONSE), frame.data]);

    case FRAME_TYPE.CONNECTION_CLOSE:
    case FRAME_TYPE.CONNECTION_CLOSE_APP:
      return encodeConnectionClose(frame);

    case FRAME_TYPE.HANDSHAKE_DONE:
      return encodeVarInt(FRAME_TYPE.HANDSHAKE_DONE);

    case FRAME_TYPE.RESET_STREAM:
      return Buffer.concat([
        encodeVarInt(FRAME_TYPE.RESET_STREAM),
        encodeVarInt(frame.streamId),
        encodeVarInt(frame.appErrorCode),
        encodeVarInt(frame.finalSize),
      ]);

    case FRAME_TYPE.STOP_SENDING:
      return Buffer.concat([
        encodeVarInt(FRAME_TYPE.STOP_SENDING),
        encodeVarInt(frame.streamId),
        encodeVarInt(frame.appErrorCode),
      ]);

    case FRAME_TYPE.NEW_TOKEN:
      return Buffer.concat([
        encodeVarInt(FRAME_TYPE.NEW_TOKEN),
        encodeVarInt(frame.token.length),
        frame.token,
      ]);

    case FRAME_TYPE.DATAGRAM:
      return Buffer.concat([encodeVarInt(FRAME_TYPE.DATAGRAM), frame.data]);

    case FRAME_TYPE.DATAGRAM_WITH_LEN:
      return Buffer.concat([
        encodeVarInt(FRAME_TYPE.DATAGRAM_WITH_LEN),
        encodeVarInt(frame.data.length),
        frame.data,
      ]);

    default:
      throw new Error(`Cannot encode frame type: ${frame.type}`);
  }
}

function encodeAckFrame(frame) {
  const parts = [encodeVarInt(frame.type === FRAME_TYPE.ACK_ECN ? FRAME_TYPE.ACK_ECN : FRAME_TYPE.ACK)];

  const ranges = frame.ranges;
  const largestAck = ranges[0].end;
  const firstRange = ranges[0].end - ranges[0].start;

  parts.push(encodeVarInt(largestAck));
  parts.push(encodeVarInt(frame.ackDelay));
  parts.push(encodeVarInt(ranges.length - 1));
  parts.push(encodeVarInt(firstRange));

  for (let i = 1; i < ranges.length; i++) {
    const gap = ranges[i - 1].start - ranges[i].end - 2;
    const rangeLen = ranges[i].end - ranges[i].start;
    parts.push(encodeVarInt(gap));
    parts.push(encodeVarInt(rangeLen));
  }

  if (frame.type === FRAME_TYPE.ACK_ECN) {
    parts.push(encodeVarInt(frame.ect0 || 0));
    parts.push(encodeVarInt(frame.ect1 || 0));
    parts.push(encodeVarInt(frame.ecnCe || 0));
  }

  return Buffer.concat(parts);
}

function encodeCryptoFrame(frame) {
  return Buffer.concat([
    encodeVarInt(FRAME_TYPE.CRYPTO),
    encodeVarInt(frame.offset),
    encodeVarInt(frame.data.length),
    frame.data,
  ]);
}

function encodeStreamFrame(frame) {
  let typeByte = 0x08;
  if (frame.offset > 0) typeByte |= 0x04;
  typeByte |= 0x02; // always include length
  if (frame.fin) typeByte |= 0x01;

  const parts = [encodeVarInt(typeByte)];
  parts.push(encodeVarInt(frame.streamId));
  if (frame.offset > 0) parts.push(encodeVarInt(frame.offset));
  parts.push(encodeVarInt(frame.data.length));
  parts.push(frame.data);

  return Buffer.concat(parts);
}

function encodeNewConnectionId(frame) {
  return Buffer.concat([
    encodeVarInt(FRAME_TYPE.NEW_CONNECTION_ID),
    encodeVarInt(frame.sequenceNumber),
    encodeVarInt(frame.retirePriorTo),
    Buffer.from([frame.connectionId.length]),
    frame.connectionId,
    frame.statelessResetToken,
  ]);
}

function encodeConnectionClose(frame) {
  const reasonBuf = Buffer.from(frame.reasonPhrase || '', 'utf8');
  const parts = [encodeVarInt(frame.type)];
  parts.push(encodeVarInt(frame.errorCode));
  if (frame.type === FRAME_TYPE.CONNECTION_CLOSE) {
    parts.push(encodeVarInt(frame.triggerFrameType || 0));
  }
  parts.push(encodeVarInt(reasonBuf.length));
  if (reasonBuf.length > 0) parts.push(reasonBuf);
  return Buffer.concat(parts);
}

module.exports = { decodeFrames, encodeFrame };