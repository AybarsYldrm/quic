'use strict';

/**
 * Structured Logger for QUIC/HTTP3 Stack
 *
 * Levels: ERROR=0, WARN=1, INFO=2, DEBUG=3, TRACE=4
 * Toggle via QUIC_LOG_LEVEL env var (default: WARN)
 * Toggle specific modules via QUIC_LOG_MODULES (comma-separated)
 */

const LOG_LEVEL = {
  ERROR: 0,
  WARN:  1,
  INFO:  2,
  DEBUG: 3,
  TRACE: 4,
};

const LEVEL_NAMES = ['ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE'];

const LEVEL_COLORS = {
  0: '\x1b[31m',  // red
  1: '\x1b[33m',  // yellow
  2: '\x1b[36m',  // cyan
  3: '\x1b[37m',  // white
  4: '\x1b[90m',  // gray
};
const RESET = '\x1b[0m';

function parseLevel(str) {
  if (!str) return LOG_LEVEL.WARN;
  const upper = str.toUpperCase();
  if (LOG_LEVEL[upper] !== undefined) return LOG_LEVEL[upper];
  const num = parseInt(str, 10);
  if (num >= 0 && num <= 4) return num;
  return LOG_LEVEL.WARN;
}

const globalLevel = parseLevel(process.env.QUIC_LOG_LEVEL || process.env.QUIC_DEBUG);
const enabledModules = process.env.QUIC_LOG_MODULES
  ? new Set(process.env.QUIC_LOG_MODULES.split(',').map(s => s.trim().toLowerCase()))
  : null;

class Logger {
  constructor(module) {
    this.module = module;
    this.moduleLower = module.toLowerCase();
  }

  _shouldLog(level) {
    if (level > globalLevel) return false;
    if (enabledModules && !enabledModules.has(this.moduleLower)) return false;
    return true;
  }

  _log(level, args) {
    if (!this._shouldLog(level)) return;
    const ts = new Date().toISOString().slice(11, 23);
    const color = LEVEL_COLORS[level] || '';
    const prefix = `${color}[${ts}] [${LEVEL_NAMES[level]}] [${this.module}]${RESET}`;
    console.log(prefix, ...args);
  }

  error(...args) { this._log(LOG_LEVEL.ERROR, args); }
  warn(...args)  { this._log(LOG_LEVEL.WARN, args); }
  info(...args)  { this._log(LOG_LEVEL.INFO, args); }
  debug(...args) { this._log(LOG_LEVEL.DEBUG, args); }
  trace(...args) { this._log(LOG_LEVEL.TRACE, args); }
}

function createLogger(module) {
  return new Logger(module);
}

module.exports = { Logger, createLogger, LOG_LEVEL };
