'use strict';

// HTTP/2 Flow Control (RFC 7540 §6.9)

class FlowController {
  constructor(initialWindowSize = 65535) {
    this.connectionSendWindow = initialWindowSize;
    this.connectionRecvWindow = initialWindowSize;
    this.initialWindowSize = initialWindowSize;
  }

  // Update connection-level send window
  updateConnectionSendWindow(increment) {
    this.connectionSendWindow += increment;
    if (this.connectionSendWindow > 0x7fffffff) {
      throw new Error('FLOW_CONTROL_ERROR: window size overflow');
    }
  }

  // Consume connection-level send window
  consumeSendWindow(size) {
    if (size > this.connectionSendWindow) {
      return false; // Not enough window
    }
    this.connectionSendWindow -= size;
    return true;
  }

  // Consume connection-level recv window and check if update needed
  consumeRecvWindow(size) {
    this.connectionRecvWindow -= size;

    // Send WINDOW_UPDATE when half consumed
    if (this.connectionRecvWindow < this.initialWindowSize / 2) {
      const increment = this.initialWindowSize - this.connectionRecvWindow;
      this.connectionRecvWindow = this.initialWindowSize;
      return increment; // Return amount to send as WINDOW_UPDATE
    }
    return 0;
  }

  // When SETTINGS changes initial window size, adjust all streams
  updateInitialWindowSize(newSize) {
    const delta = newSize - this.initialWindowSize;
    this.initialWindowSize = newSize;
    return delta; // Apply to all stream send windows
  }
}

module.exports = {
  FlowController
};