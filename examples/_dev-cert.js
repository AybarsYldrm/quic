'use strict';

/**
 * Generates a throwaway self-signed EC certificate so these examples run
 * standalone with `node examples/whatever.js`, no external cert files
 * needed. For a real deployment, load a real certificate/key instead:
 *
 *   const cert = fs.readFileSync('/path/to/fullchain.pem');
 *   const key  = fs.readFileSync('/path/to/privkey.pem');
 *
 * and point clients at it with `ca` (or set rejectUnauthorized:false only
 * for local development against self-signed certs like this one).
 */
const { generateEcRootCA, generateEcEndEntityCert, ecPrivToPem } = require('@fitfak/ssl');

function makeDevCert(hostname = 'localhost') {
  const rootCA = generateEcRootCA();
  const leaf = generateEcEndEntityCert(rootCA, hostname);
  return {
    ca: rootCA.certPem,
    cert: leaf.certPem,
    key: ecPrivToPem(leaf),
  };
}

module.exports = { makeDevCert };
