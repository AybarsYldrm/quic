'use strict';

/**
 * Shared by quic-client.js and http2-client.js: turns an H3Request/H2Request
 * (both are EventEmitters with 'data'/'end'/'error' and a .status/.headers)
 * into a single Promise, so callers don't have to hand-roll the same
 * data/end/error wiring every time they issue a request.
 */
function collectResponse(req, protocol) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let settled = false;
    req.on('error', (err) => { if (settled) return; settled = true; reject(err); });
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      if (settled) return;
      settled = true;
      resolve({ status: req.status, headers: req.headers || {}, body: Buffer.concat(chunks), protocol });
    });
  });
}

module.exports = { collectResponse };
