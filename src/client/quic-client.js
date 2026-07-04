'use strict';

/**
 * QUIC / HTTP-3 outbound (dialing) client.
 *
 * The rest of this codebase (Transport/QuicConnection, H3Connection) already
 * implements client-mode logic, but nothing ever actually opened a UDP socket,
 * resolved DNS, wired transport.receivePacket()/sendDatagram to it, or drove
 * connect() for an outbound connection - server.js only ever *accepts*
 * inbound QUIC connections. That's why creating a "client" against a real
 * endpoint never worked: the ClientHello was built correctly but nothing
 * ever put it on the wire, and nothing was listening for a reply.
 */

const dgram = require('dgram');
const dns   = require('dns');
const { Transport } = require('../connection/connection');
const { H3Connection } = require('../h3/http3');
const { SessionTicketStore } = require('../crypto/zero-rtt');
const { QUIC_VERSION_1 } = require('../constants');
const { createLogger } = require('../utils/logger');

const log = createLogger('QuicClient');

function resolveHost(host) {
  return new Promise((resolve, reject) => {
    dns.lookup(host, { family: 4 }, (err, address) => {
      if (err) reject(err); else resolve(address);
    });
  });
}

class QuicClient {
  constructor(options = {}) {
    // Origins that support QUIC frequently issue session tickets; sharing one
    // store across connect() calls lets later connections resume / 0-RTT.
    this.ticketStore = options.ticketStore || new SessionTicketStore();
  }

  /**
   * Dial host:port over QUIC and complete the HTTP/3 control-stream setup.
   * Resolves with { transport, h3, close() }.
   */
  connect(host, port = 443, options = {}) {
    const timeoutMs = options.timeout || 8000;

    return resolveHost(host).then((address) => new Promise((resolve, reject) => {
      const socket = dgram.createSocket('udp4');
      let settled = false;

      // Bug fixed here: this used to call socket.removeAllListeners('message')
      // unconditionally on *any* settlement, including success - which tore
      // down the exact listener that feeds all post-handshake traffic into
      // transport.receivePacket(). The handshake would complete, connect()
      // would resolve, and then every single response packet the server
      // sent afterwards (HTTP/3 responses included) was silently dropped by
      // a socket with no one listening, hanging forever. The 'message'
      // listener now only comes down when the connection attempt actually
      // fails and the socket is being torn down with it.
      const settleFailure = (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.removeAllListeners('message');
        reject(err);
      };
      const settleSuccess = (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      };

      const timer = setTimeout(() => {
        try { socket.close(); } catch (_) {}
        settleFailure(new Error(`QUIC handshake to ${host}:${port} timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      if (typeof timer.unref === 'function') timer.unref();

      const transport = new Transport({
        transport:          'quic',
        isServer:            false,
        version:              options.version || QUIC_VERSION_1,
        cert:                 options.cert || null,
        key:                  options.key  || null,
        alpn:                 options.alpn || ['h3'],
        // Bug fixed here: previously nothing set serverName to the real
        // dial target, so TLS fell back to its 'localhost' default SNI -
        // which real servers (including SNI-routed edges) will reject or
        // mis-route.
        serverName:           host,
        cipherSuites:         options.cipherSuites,
        transportParams:      options.transportParams,
        ticketStore:          this.ticketStore,
        // Unlike the TLS class's own (permissive) default, a client dialing
        // an arbitrary internet host must verify the peer by default.
        rejectUnauthorized:   options.rejectUnauthorized !== undefined ? options.rejectUnauthorized : true,
        ca:                   options.ca || null,
        keepaliveInterval:    options.keepaliveInterval || 0,
        sendDatagram: (data, addr, p) => {
          socket.send(data, p, addr, (err) => {
            if (err) log.debug(`[QUIC] UDP send error: ${err.message}`);
          });
        },
        remoteAddress: address,
        remotePort:    port,
      });

      socket.on('message', (msg) => {
        try { transport.receivePacket(msg); } catch (e) { log.debug(`[QUIC] receivePacket error: ${e.message}`); }
      });

      socket.on('error', (err) => settleFailure(err));

      transport.on('versionNegotiation', (versions) => {
        try { socket.close(); } catch (_) {}
        const list = versions.map((v) => '0x' + v.toString(16)).join(', ');
        settleFailure(new Error(`Server rejected QUIC v1; it only offered: [${list}]`));
      });

      transport.on('connected', () => {
        const h3 = new H3Connection(transport, {
          isServer:           false,
          enableWebTransport: options.enableWebTransport || false,
        });
        settleSuccess({
          transport,
          h3,
          close: (errorCode = 0) => {
            try { transport.close(errorCode); } catch (_) {}
            try { socket.removeAllListeners('message'); } catch (_) {}
            try { socket.close(); } catch (_) {}
          },
        });
      });

      transport.on('error', (err) => {
        if (!settled) { try { socket.close(); } catch (_) {} }
        settleFailure(err);
      });

      transport.connect();
    }));
  }
}

function connectQuic(host, port, options) {
  return new QuicClient(options).connect(host, port, options);
}

module.exports = { QuicClient, connectQuic };
