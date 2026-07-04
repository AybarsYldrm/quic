'use strict';

// HTTP/2 Server Push (RFC 7540 §8.2)
const { buildPushPromiseFrame } = require('../frame/codec.js');

class ServerPush {
  constructor(connection) {
    this.connection = connection;
    this.nextPushStreamId = 2; // Server push uses even IDs
  }

  // Send a PUSH_PROMISE and create the promised stream
  push(associatedStreamId, requestHeaders) {
    const promisedStreamId = this.nextPushStreamId;
    this.nextPushStreamId += 2;

    // Encode headers for the promised request
    const headerList = [];
    for (const [k, v] of Object.entries(requestHeaders)) {
      headerList.push([k.toLowerCase(), String(v)]);
    }

    const headerBlock = this.connection.hpackEncoder.encode(headerList);
    const frame = buildPushPromiseFrame(associatedStreamId, promisedStreamId, headerBlock);

    this.connection.tlsSocket.write(frame);

    // Create the promised stream
    const stream = this.connection._createStream(promisedStreamId);
    stream.state = 'reserved_local';

    return stream;
  }
}

module.exports = {
  ServerPush
};