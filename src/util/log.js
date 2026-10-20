'use strict';

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3, trace: 4 };
let currentLevel = LEVELS.info;
let logFile = null;

function setLevel(name) {
  if (name in LEVELS) currentLevel = LEVELS[name];
}

function setFile(file) {
  logFile = file;
}

function ts() {
  return new Date().toISOString();
}

function write(level, args) {
  if (LEVELS[level] > currentLevel) return;
  const line = `${ts()} [${level.toUpperCase()}] ${args
    .map((a) => {
      if (typeof a === 'string') return a;
      if (a instanceof Error) return a.stack || a.message;
      try {
        return JSON.stringify(a);
      } catch {
        return String(a);
      }
    })
    .join(' ')}`;
  // eslint-disable-next-line no-console
  (level === 'error' ? console.error : console.log)(line);
  if (logFile) {
    try {
      require('fs').appendFileSync(logFile, line + '\n');
    } catch {
      /* logging must never crash the process */
    }
  }
}

module.exports = {
  setLevel,
  setFile,
  error: (...a) => write('error', a),
  warn: (...a) => write('warn', a),
  info: (...a) => write('info', a),
  debug: (...a) => write('debug', a),
  trace: (...a) => write('trace', a),
};
