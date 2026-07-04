'use strict';

/**
 * 0-RTT (early data) safety policy.
 *
 * 0-RTT data carried in TLS 1.3 early_data is REPLAYABLE by an on-path
 * attacker. RFC 8446 §8 explicitly allows replay; it is the application's
 * responsibility to gate which requests may be served from 0-RTT.
 *
 * This module provides three pieces of policy that a server should compose:
 *
 *   1. isSafeEarlyDataRequest(req)
 *      - default classifier: only idempotent HTTP methods (GET, HEAD, OPTIONS)
 *        with no body.
 *
 *   2. ReplayCache
 *      - in-memory anti-replay cache keyed by ticket nonce. Each (nonce, key)
 *        pair may only be observed once during the cache TTL. Bounded size.
 *
 *   3. composePolicy({ allowMethods, requireSafe, replayCache, custom })
 *      - returns a single (req, ctx) -> { accept, reason } function suitable
 *        for plugging into QuicServer's onEarlyData hook.
 *
 * No external deps. No persistent state — tickets that survive a process
 * restart fall back to the safe-method classifier; if you want stronger
 * anti-replay across restarts, plug a Redis/sqlite-backed ReplayCache by
 * subclassing.
 */

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function isSafeEarlyDataRequest(req) {
  if (!req) return false;
  const method = String(req.method || '').toUpperCase();
  if (!SAFE_METHODS.has(method)) return false;
  // No body — safe methods MUST NOT carry a body in our policy.
  if (req.body && req.body.length > 0) return false;
  if (req.headers && req.headers['content-length'] && Number(req.headers['content-length']) > 0) {
    return false;
  }
  return true;
}

class ReplayCache {
  /**
   * @param {object} opts
   * @param {number} [opts.ttlMs=10000]   how long to remember a nonce
   * @param {number} [opts.maxSize=10000] hard cap on cache entries
   */
  constructor(opts = {}) {
    this.ttlMs   = opts.ttlMs   || 10000;
    this.maxSize = opts.maxSize || 10000;
    this._entries = new Map();   // nonceHex -> expiresAt (ms epoch)
  }

  /**
   * Returns true if `nonce` (Buffer | string) has been seen within ttlMs;
   * otherwise records it and returns false.
   */
  checkAndRecord(nonce) {
    if (!nonce) return false;
    const key = Buffer.isBuffer(nonce) ? nonce.toString('hex') : String(nonce);
    const now = Date.now();
    this._sweep(now);
    const seenAt = this._entries.get(key);
    if (seenAt !== undefined && seenAt > now) return true;  // replay
    this._entries.set(key, now + this.ttlMs);
    if (this._entries.size > this.maxSize) this._evict();
    return false;
  }

  _sweep(now) {
    // Cheap incremental sweep: only scan if recently grew.
    if (this._entries.size < this.maxSize / 2) return;
    for (const [k, exp] of this._entries) {
      if (exp <= now) this._entries.delete(k);
    }
  }

  _evict() {
    // Drop the oldest 10% by insertion order (Map is insertion-ordered).
    const drop = Math.ceil(this.maxSize * 0.1);
    let i = 0;
    for (const k of this._entries.keys()) {
      this._entries.delete(k);
      if (++i >= drop) break;
    }
  }

  size() { return this._entries.size; }
  clear() { this._entries.clear(); }
}

/**
 * Compose a single policy function from primitives.
 *
 * @param {object} opts
 * @param {Set<string>|null} [opts.allowMethods=null]   override safe-method set
 * @param {boolean}          [opts.requireSafe=true]    enforce isSafeEarlyDataRequest
 * @param {ReplayCache|null} [opts.replayCache=null]    nonce replay protection
 * @param {Function|null}    [opts.custom=null]         additional (req, ctx) -> bool
 * @returns {(req, ctx?) => { accept: boolean, reason: string }}
 */
function composePolicy(opts = {}) {
  const requireSafe  = opts.requireSafe !== false;
  const allowMethods = opts.allowMethods || SAFE_METHODS;
  const replayCache  = opts.replayCache || null;
  const custom       = typeof opts.custom === 'function' ? opts.custom : null;

  return function policy(req, ctx) {
    if (requireSafe && !isSafeEarlyDataRequest(req)) {
      return { accept: false, reason: 'unsafe-method-or-body' };
    }
    const method = String(req && req.method || '').toUpperCase();
    if (!allowMethods.has(method)) {
      return { accept: false, reason: 'method-not-allowed' };
    }
    if (replayCache && ctx && ctx.ticketNonce) {
      if (replayCache.checkAndRecord(ctx.ticketNonce)) {
        return { accept: false, reason: 'replay' };
      }
    }
    if (custom && !custom(req, ctx)) {
      return { accept: false, reason: 'custom-deny' };
    }
    return { accept: true, reason: 'ok' };
  };
}

module.exports = {
  SAFE_METHODS,
  isSafeEarlyDataRequest,
  ReplayCache,
  composePolicy,
};
