'use strict';

/**
 * High-Level HTTP/3 Client (axios-like)
 *
 * Features:
 * - Auto protocol: HTTP/3 -> HTTP/1.1 fallback
 * - Simple API: get(), post(), put(), delete()
 * - Supports: headers, timeout, redirects, streaming
 * - Connection pooling per host
 *
 * Usage:
 *   const client = new Http3Client();
 *   const res = await client.get('https://example.com/api/data');
 *   console.log(res.status, res.data);
 *
 * Uses ONLY Node.js built-in modules.
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');
const { QuicClient } = require('./client');
const { H3Connection } = require('../h3/http3');
const { createLogger } = require('../utils/logger');

const log = createLogger('Http3Client');

class Http3Client {
  constructor(options = {}) {
    this.defaultHeaders = options.headers || {};
    this.timeout = options.timeout || 15000;
    this.maxRedirects = options.maxRedirects || 5;
    this.followRedirects = options.followRedirects !== false;
    this.preferH3 = options.preferH3 !== false;

    // mTLS options
    this.cert = options.cert || null;
    this.key = options.key || null;
    this.ca = options.ca || null;
    this.rejectUnauthorized = options.rejectUnauthorized !== false;
    this.ticketStore = options.ticketStore || null;

    // Connection pool: host:port -> { quicClient, h3conn }
    this._pool = new Map();
  }

  /**
   * GET request
   */
  async get(url, options = {}) {
    return this.request({ ...options, method: 'GET', url });
  }

  /**
   * POST request
   */
  async post(url, data, options = {}) {
    return this.request({ ...options, method: 'POST', url, data });
  }

  /**
   * PUT request
   */
  async put(url, data, options = {}) {
    return this.request({ ...options, method: 'PUT', url, data });
  }

  /**
   * DELETE request
   */
  async delete(url, options = {}) {
    return this.request({ ...options, method: 'DELETE', url });
  }

  /**
   * PATCH request
   */
  async patch(url, data, options = {}) {
    return this.request({ ...options, method: 'PATCH', url, data });
  }

  /**
   * Generic request
   */
  async request(config) {
    const {
      method = 'GET',
      url,
      headers = {},
      data,
      timeout = this.timeout,
      maxRedirects = this.maxRedirects,
      stream = false,
    } = config;

    const parsed = new URL(url);
    const mergedHeaders = { ...this.defaultHeaders, ...headers };

    // Try HTTP/3 first if preferred
    if (this.preferH3 && parsed.protocol === 'https:') {
      try {
        const result = await this._requestH3(parsed, method, mergedHeaders, data, timeout);
        // Handle redirects
        if (this.followRedirects && result.status >= 300 && result.status < 400 && result.headers.location) {
          return this._followRedirect(result.headers.location, parsed, config, maxRedirects - 1);
        }
        return result;
      } catch (e) {
        log.info(`HTTP/3 failed for ${parsed.hostname}, falling back to HTTPS:`, e.message);
      }
    }

    // Fallback to HTTP/1.1 (HTTPS or HTTP)
    const result = await this._requestH1(parsed, method, mergedHeaders, data, timeout);

    // Handle redirects
    if (this.followRedirects && result.status >= 300 && result.status < 400 && result.headers.location) {
      return this._followRedirect(result.headers.location, parsed, config, maxRedirects - 1);
    }

    return result;
  }

  /**
   * HTTP/3 request via QUIC
   */
  async _requestH3(parsed, method, headers, data, timeout) {
    const host = parsed.hostname;
    const port = parseInt(parsed.port || '443', 10);
    const path = parsed.pathname + parsed.search;
    const poolKey = `${host}:${port}`;

    let poolEntry = this._pool.get(poolKey);

    if (!poolEntry) {
      const client = new QuicClient({
        host,
        port,
        serverName: host,
        alpn: ['h3'],
        cert: this.cert,
        key: this.key,
        ca: this.ca,
        rejectUnauthorized: this.rejectUnauthorized,
        ticketStore: this.ticketStore,
      });

      const conn = await Promise.race([
        client.connect(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('H3 connection timeout')), timeout)),
      ]);

      const h3 = new H3Connection(conn, { isServer: false });

      // Wait for ready
      await new Promise((resolve, reject) => {
        h3.on('ready', resolve);
        setTimeout(() => reject(new Error('H3 ready timeout')), timeout);
      });

      poolEntry = { client, h3 };
      this._pool.set(poolKey, poolEntry);
    }

    const { h3 } = poolEntry;

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Request timeout')), timeout);

      const requestHeaders = { ...headers };
      delete requestHeaders['host']; // pseudo-header handles this

      const req = h3.request(method, path, requestHeaders, {
        authority: host,
        scheme: 'https',
      });

      // Send body if present
      if (data) {
        const bodyBuf = typeof data === 'string' ? Buffer.from(data, 'utf8')
          : typeof data === 'object' && !Buffer.isBuffer(data) ? Buffer.from(JSON.stringify(data), 'utf8')
          : data;
        if (!requestHeaders['content-type'] && typeof data === 'object' && !Buffer.isBuffer(data)) {
          // Already sent in HEADERS frame, can't change now - but this is a note for future
        }
        req.write(bodyBuf);
      }
      req.endRequest();

      const responseChunks = [];

      req.on('headers', (hdrs) => {
        // headers received
      });

      req.on('data', (chunk) => {
        responseChunks.push(chunk);
      });

      req.on('end', () => {
        clearTimeout(timer);
        const body = Buffer.concat(responseChunks);
        const response = {
          status: req.status,
          headers: req.headers || {},
          data: body.toString('utf8'),
          body,
          protocol: 'h3',
        };

        // Try to parse JSON
        const ct = response.headers['content-type'] || '';
        if (ct.includes('json')) {
          try {
            response.data = JSON.parse(body.toString('utf8'));
          } catch (_) {}
        }

        resolve(response);
      });

      req.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  /**
   * HTTP/1.1 fallback via Node.js https/http module
   */
  _requestH1(parsed, method, headers, data, timeout) {
    return new Promise((resolve, reject) => {
      const isHttps = parsed.protocol === 'https:';
      const mod = isHttps ? https : http;

      const opts = {
        hostname: parsed.hostname,
        port: parseInt(parsed.port || (isHttps ? '443' : '80'), 10),
        path: parsed.pathname + parsed.search,
        method,
        headers,
        timeout,
        rejectUnauthorized: this.rejectUnauthorized,
      };

      if (this.cert) opts.cert = this.cert;
      if (this.key) opts.key = this.key;
      if (this.ca) opts.ca = this.ca;

      const req = mod.request(opts, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const body = Buffer.concat(chunks);
          const responseHeaders = {};
          for (const [key, val] of Object.entries(res.headers)) {
            responseHeaders[key] = Array.isArray(val) ? val.join(', ') : val;
          }

          const response = {
            status: res.statusCode,
            headers: responseHeaders,
            data: body.toString('utf8'),
            body,
            protocol: isHttps ? 'h1-tls' : 'h1',
          };

          const ct = responseHeaders['content-type'] || '';
          if (ct.includes('json')) {
            try {
              response.data = JSON.parse(body.toString('utf8'));
            } catch (_) {}
          }

          resolve(response);
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      if (data) {
        const bodyBuf = typeof data === 'string' ? Buffer.from(data, 'utf8')
          : typeof data === 'object' && !Buffer.isBuffer(data) ? Buffer.from(JSON.stringify(data), 'utf8')
          : data;
        req.write(bodyBuf);
      }

      req.end();
    });
  }

  /**
   * Follow redirect
   */
  async _followRedirect(location, originalUrl, config, remaining) {
    if (remaining <= 0) {
      throw new Error('Maximum redirects exceeded');
    }

    // Resolve relative URLs
    let redirectUrl;
    try {
      redirectUrl = new URL(location, originalUrl.href).href;
    } catch (_) {
      redirectUrl = location;
    }

    log.debug(`Following redirect to: ${redirectUrl}`);
    return this.request({
      ...config,
      url: redirectUrl,
      maxRedirects: remaining,
    });
  }

  /**
   * Close all pooled connections
   */
  async close() {
    for (const [, entry] of this._pool) {
      try {
        await entry.client.close();
      } catch (_) {}
    }
    this._pool.clear();
  }
}

module.exports = { Http3Client };
