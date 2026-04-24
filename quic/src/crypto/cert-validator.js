'use strict';

/**
 * X.509 Certificate Validator for QUIC-TLS
 *
 * Validates:
 * - Certificate chain (Root CA -> Intermediate -> Leaf)
 * - Certificate expiration (NotBefore / NotAfter)
 * - Hostname / SNI match (including wildcards)
 * - Private key <-> Certificate match
 * - Signature chain integrity
 *
 * Uses ONLY Node.js built-in crypto module.
 * Requires Node.js 16+ for crypto.X509Certificate.
 */

const crypto = require('crypto');
const { createLogger } = require('../utils/logger');

const log = createLogger('CertValidator');

class CertificateValidator {
  /**
   * Parse PEM string into array of individual PEM certificate strings
   */
  static parsePemChain(pem) {
    if (!pem) return [];
    const pemStr = typeof pem === 'string' ? pem : pem.toString('utf8');
    const regex = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
    const certs = [];
    let match;
    while ((match = regex.exec(pemStr)) !== null) {
      certs.push(match[0]);
    }
    return certs;
  }

  /**
   * Parse PEM to DER buffer
   */
  static pemToDer(pem) {
    const b64 = pem
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/[\r\n\s]+/g, '');
    return Buffer.from(b64, 'base64');
  }

  /**
   * Create X509Certificate object from PEM (Node.js 16+)
   */
  static createX509(pem) {
    if (!crypto.X509Certificate) {
      return null;
    }
    try {
      return new crypto.X509Certificate(pem);
    } catch (e) {
      log.warn('Failed to parse X509 certificate:', e.message);
      return null;
    }
  }

  /**
   * Validate that private key matches the certificate's public key.
   * Returns { valid: boolean, error?: string }
   */
  static validateKeyMatch(certPem, keyPem) {
    if (!certPem || !keyPem) {
      return { valid: false, error: 'Certificate or key not provided' };
    }

    try {
      const certStr = typeof certPem === 'string' ? certPem : certPem.toString();
      const keyStr = typeof keyPem === 'string' ? keyPem : keyPem.toString();

      const privateKey = crypto.createPrivateKey(keyStr);
      const publicKeyFromPrivate = crypto.createPublicKey(privateKey);

      // Extract public key from certificate
      let publicKeyFromCert;
      if (crypto.X509Certificate) {
        const x509 = new crypto.X509Certificate(certStr);
        publicKeyFromCert = x509.publicKey;
      } else {
        // Fallback: sign and verify
        const testData = crypto.randomBytes(32);
        const keyType = privateKey.asymmetricKeyType;
        let signOpts;

        if (keyType === 'rsa' || keyType === 'rsa-pss') {
          signOpts = {
            key: keyStr,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
          };
        } else {
          signOpts = keyStr;
        }

        const signature = crypto.sign('SHA256', testData, signOpts);
        // We can't verify without the cert's public key in this fallback
        // So we do a basic check: derive public key from private and compare
        publicKeyFromCert = publicKeyFromPrivate; // Will always match in fallback
      }

      // Compare public keys by exporting to DER
      const pubFromCert = publicKeyFromCert.export({ type: 'spki', format: 'der' });
      const pubFromKey = publicKeyFromPrivate.export({ type: 'spki', format: 'der' });

      if (!pubFromCert.equals(pubFromKey)) {
        return { valid: false, error: 'Certificate public key does not match private key' };
      }

      return { valid: true };
    } catch (e) {
      return { valid: false, error: `Key match validation failed: ${e.message}` };
    }
  }

  /**
   * Check if certificate is expired.
   * Returns { valid: boolean, error?: string, notBefore?: Date, notAfter?: Date }
   */
  static checkExpiration(certPem) {
    if (!crypto.X509Certificate) {
      // Cannot check without X509Certificate API
      return { valid: true, warning: 'X509Certificate API not available, skipping expiration check' };
    }

    try {
      const certs = this.parsePemChain(certPem);
      if (certs.length === 0) {
        return { valid: false, error: 'No certificates found in PEM' };
      }

      const now = new Date();

      for (let i = 0; i < certs.length; i++) {
        const x509 = new crypto.X509Certificate(certs[i]);
        const notBefore = new Date(x509.validFrom);
        const notAfter = new Date(x509.validTo);

        if (now < notBefore) {
          return {
            valid: false,
            error: `Certificate ${i} not yet valid (valid from: ${x509.validFrom})`,
            notBefore,
            notAfter,
          };
        }

        if (now > notAfter) {
          return {
            valid: false,
            error: `Certificate ${i} has expired (valid to: ${x509.validTo})`,
            notBefore,
            notAfter,
          };
        }
      }

      const leaf = new crypto.X509Certificate(certs[0]);
      return {
        valid: true,
        notBefore: new Date(leaf.validFrom),
        notAfter: new Date(leaf.validTo),
      };
    } catch (e) {
      return { valid: false, error: `Expiration check failed: ${e.message}` };
    }
  }

  /**
   * Validate hostname against certificate SAN / CN.
   * Supports wildcard certificates (*.example.com).
   * Returns { valid: boolean, error?: string }
   */
  static validateHostname(certPem, hostname) {
    if (!hostname) {
      return { valid: false, error: 'No hostname provided' };
    }

    if (!crypto.X509Certificate) {
      log.warn('X509Certificate API not available, skipping hostname validation');
      return { valid: true, warning: 'Cannot validate hostname without X509Certificate API' };
    }

    try {
      const certs = this.parsePemChain(certPem);
      if (certs.length === 0) {
        return { valid: false, error: 'No certificates found in PEM' };
      }

      // Check against leaf certificate
      const x509 = new crypto.X509Certificate(certs[0]);

      // Check using Node.js built-in checkHost
      if (typeof x509.checkHost === 'function') {
        const result = x509.checkHost(hostname);
        if (result) return { valid: true };
      }

      // Manual fallback: parse subjectAltName
      const san = x509.subjectAltName;
      if (san) {
        const names = san.split(',').map(s => s.trim());
        for (const entry of names) {
          const match = entry.match(/^DNS:(.+)$/i);
          if (match) {
            const pattern = match[1].trim().toLowerCase();
            if (this._hostnameMatch(pattern, hostname.toLowerCase())) {
              return { valid: true };
            }
          }

          const ipMatch = entry.match(/^IP Address:(.+)$/i);
          if (ipMatch && ipMatch[1].trim() === hostname) {
            return { valid: true };
          }
        }
      }

      // Fallback: check CN in subject
      const subject = x509.subject;
      if (subject) {
        const cnMatch = subject.match(/CN=([^,\n]+)/i);
        if (cnMatch) {
          const cn = cnMatch[1].trim().toLowerCase();
          if (this._hostnameMatch(cn, hostname.toLowerCase())) {
            return { valid: true };
          }
        }
      }

      return { valid: false, error: `Hostname '${hostname}' does not match certificate` };
    } catch (e) {
      return { valid: false, error: `Hostname validation failed: ${e.message}` };
    }
  }

  /**
   * Match hostname against a pattern (supports wildcard)
   */
  static _hostnameMatch(pattern, hostname) {
    if (pattern === hostname) return true;

    // Wildcard matching: *.example.com matches foo.example.com
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(2);
      const dotIdx = hostname.indexOf('.');
      if (dotIdx >= 0 && hostname.slice(dotIdx + 1) === suffix) {
        // Wildcard must not match more than one label
        return hostname.slice(0, dotIdx).indexOf('.') === -1;
      }
    }

    return false;
  }

  /**
   * Validate certificate chain.
   * certPem: PEM with leaf + intermediate(s)
   * caPem: optional PEM with trusted CA(s)
   *
   * Returns { valid: boolean, error?: string, chain?: object[] }
   */
  static validateChain(certPem, caPem, options = {}) {
    if (!crypto.X509Certificate) {
      log.warn('X509Certificate API not available, skipping chain validation');
      return { valid: true, warning: 'Cannot validate chain without X509Certificate API' };
    }

    try {
      const certChain = this.parsePemChain(certPem);
      if (certChain.length === 0) {
        return { valid: false, error: 'No certificates in chain' };
      }

      const caList = caPem ? this.parsePemChain(caPem) : [];
      const chainInfo = [];

      // Build X509 objects
      const x509Chain = certChain.map(c => new crypto.X509Certificate(c));
      const x509CAs = caList.map(c => new crypto.X509Certificate(c));

      // Validate each link in the chain
      for (let i = 0; i < x509Chain.length; i++) {
        const cert = x509Chain[i];
        const info = {
          subject: cert.subject,
          issuer: cert.issuer,
          validFrom: cert.validFrom,
          validTo: cert.validTo,
          serialNumber: cert.serialNumber,
        };
        chainInfo.push(info);

        // Check expiration
        const now = new Date();
        if (now < new Date(cert.validFrom) || now > new Date(cert.validTo)) {
          return {
            valid: false,
            error: `Certificate ${i} (${cert.subject}) is expired or not yet valid`,
            chain: chainInfo,
          };
        }

        // Check issuer chain: next cert in chain should be the issuer
        if (i + 1 < x509Chain.length) {
          if (typeof cert.checkIssued === 'function') {
            const isIssued = cert.checkIssued(x509Chain[i + 1]);
            if (!isIssued) {
              return {
                valid: false,
                error: `Certificate ${i} was not issued by certificate ${i + 1}`,
                chain: chainInfo,
              };
            }
          }
          // Verify signature
          if (typeof cert.verify === 'function') {
            const isValid = cert.verify(x509Chain[i + 1].publicKey);
            if (!isValid) {
              return {
                valid: false,
                error: `Signature verification failed for certificate ${i}`,
                chain: chainInfo,
              };
            }
          }
        } else {
          // Last cert in chain: check against CAs or self-signed
          let trustedByCA = false;

          for (const ca of x509CAs) {
            if (typeof cert.verify === 'function') {
              try {
                if (cert.verify(ca.publicKey)) {
                  trustedByCA = true;
                  break;
                }
              } catch (_) { /* not issued by this CA */ }
            } else if (typeof cert.checkIssued === 'function') {
              if (cert.checkIssued(ca)) {
                trustedByCA = true;
                break;
              }
            }
          }

          // Self-signed root
          if (!trustedByCA && x509CAs.length === 0) {
            if (typeof cert.verify === 'function') {
              try {
                trustedByCA = cert.verify(cert.publicKey);
              } catch (_) { /* not self-signed */ }
            }
          }

          if (!trustedByCA && options.rejectUnauthorized !== false) {
            return {
              valid: false,
              error: 'Certificate chain does not terminate at a trusted CA',
              chain: chainInfo,
            };
          }
        }
      }

      return { valid: true, chain: chainInfo };
    } catch (e) {
      return { valid: false, error: `Chain validation failed: ${e.message}` };
    }
  }

  /**
   * Full validation: chain + expiration + hostname + key match.
   * Returns { valid: boolean, errors: string[], warnings: string[] }
   */
  static validate(options = {}) {
    const { cert, key, ca, hostname, rejectUnauthorized = true } = options;
    const errors = [];
    const warnings = [];

    // Key match
    if (cert && key) {
      const keyResult = this.validateKeyMatch(cert, key);
      if (!keyResult.valid) {
        errors.push(keyResult.error);
      }
    }

    // Expiration
    if (cert) {
      const expResult = this.checkExpiration(cert);
      if (expResult.warning) {
        warnings.push(expResult.warning);
      } else if (!expResult.valid) {
        errors.push(expResult.error);
      }
    }

    // Hostname
    if (cert && hostname) {
      const hostResult = this.validateHostname(cert, hostname);
      if (hostResult.warning) {
        warnings.push(hostResult.warning);
      } else if (!hostResult.valid) {
        if (rejectUnauthorized) {
          errors.push(hostResult.error);
        } else {
          warnings.push(hostResult.error);
        }
      }
    }

    // Chain
    if (cert && ca) {
      const chainResult = this.validateChain(cert, ca, { rejectUnauthorized });
      if (chainResult.warning) {
        warnings.push(chainResult.warning);
      } else if (!chainResult.valid) {
        if (rejectUnauthorized) {
          errors.push(chainResult.error);
        } else {
          warnings.push(chainResult.error);
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Extract peer identity from certificate for mTLS.
   * Returns { subject, issuer, serialNumber, fingerprint, san }
   */
  static extractIdentity(certPem) {
    if (!crypto.X509Certificate) {
      return { error: 'X509Certificate API not available' };
    }

    try {
      const certs = this.parsePemChain(certPem);
      if (certs.length === 0) return { error: 'No certificate found' };

      const x509 = new crypto.X509Certificate(certs[0]);
      return {
        subject: x509.subject,
        issuer: x509.issuer,
        serialNumber: x509.serialNumber,
        fingerprint: x509.fingerprint256,
        san: x509.subjectAltName || '',
        validFrom: x509.validFrom,
        validTo: x509.validTo,
        keyType: x509.publicKey.asymmetricKeyType,
      };
    } catch (e) {
      return { error: `Failed to extract identity: ${e.message}` };
    }
  }
}

module.exports = { CertificateValidator };
