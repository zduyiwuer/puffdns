'use strict';

const crypto = require('crypto');
const { URL } = require('url');
const log = require('../util/log');

/** Minimal but complete HTTP toolkit: no framework, no dependencies. */

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
};

class HttpError extends Error {
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

function sendJson(res, status, body, extraHeaders = {}) {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...extraHeaders,
  });
  res.end(payload);
}

function sendText(res, status, body, contentType = 'text/plain; charset=utf-8') {
  res.writeHead(status, {
    'Content-Type': contentType,
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function sendError(res, err) {
  const status = err && err.status ? err.status : 500;
  const message = err && err.message ? err.message : 'internal error';
  const body = { error: message };
  if (err && err.details) body.details = err.details;
  if (status >= 500) log.error(`${status} ${message}`, err && err.stack ? err.stack : '');
  sendJson(res, status, body);
}

async function readBody(req, limit = 2 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new HttpError(413, 'request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function readJson(req) {
  const buf = await readBody(req);
  if (!buf.length) return {};
  try {
    return JSON.parse(buf.toString('utf8'));
  } catch {
    throw new HttpError(400, 'invalid JSON body');
  }
}

function parseCookies(req) {
  const header = req.headers.cookie;
  if (!header) return {};
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const first = String(xff).split(',')[0].trim();
    if (first) return first.replace(/^::ffff:/, '');
  }
  return String(req.socket.remoteAddress || '').replace(/^::ffff:/, '');
}

/** Signed-cookie session tokens: base64(payload).hmac */
class Session {
  constructor(secret, { ttlMs = 7 * 24 * 3600 * 1000, cookieName = 'puffdns_session' } = {}) {
    this.secret = secret;
    this.ttlMs = ttlMs;
    this.cookieName = cookieName;
  }

  sign(payload) {
    const body = Buffer.from(
      JSON.stringify({ ...payload, exp: Date.now() + this.ttlMs })
    ).toString('base64url');
    const mac = crypto.createHmac('sha256', this.secret).update(body).digest('base64url');
    return `${body}.${mac}`;
  }

  verify(token) {
    if (!token || typeof token !== 'string') return null;
    const idx = token.lastIndexOf('.');
    if (idx < 0) return null;
    const body = token.slice(0, idx);
    const mac = token.slice(idx + 1);
    const expected = crypto.createHmac('sha256', this.secret).update(body).digest('base64url');
    const a = Buffer.from(mac);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    try {
      const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
      if (!payload.exp || payload.exp < Date.now()) return null;
      return payload;
    } catch {
      return null;
    }
  }

  cookieHeader(token, { clear = false } = {}) {
    if (clear) return `${this.cookieName}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;
    return `${this.cookieName}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(this.ttlMs / 1000)}`;
  }

  fromRequest(req) {
    const cookies = parseCookies(req);
    return this.verify(cookies[this.cookieName]);
  }
}

/**
 * Tiny router with path params, e.g. /api/zones/:name/records/:id
 */
class Router {
  constructor() {
    this.routes = [];
  }

  add(method, pattern, handler, opts = {}) {
    const parts = pattern.split('/').filter(Boolean);
    this.routes.push({ method: method.toUpperCase(), parts, handler, opts, pattern });
    return this;
  }

  get(p, h, o) {
    return this.add('GET', p, h, o);
  }
  post(p, h, o) {
    return this.add('POST', p, h, o);
  }
  put(p, h, o) {
    return this.add('PUT', p, h, o);
  }
  patch(p, h, o) {
    return this.add('PATCH', p, h, o);
  }
  delete(p, h, o) {
    return this.add('DELETE', p, h, o);
  }

  match(method, pathname) {
    const segments = pathname.split('/').filter(Boolean);
    let methodMismatch = false;

    for (const route of this.routes) {
      if (route.parts.length !== segments.length) continue;
      const params = {};
      let ok = true;
      for (let i = 0; i < route.parts.length; i++) {
        const part = route.parts[i];
        if (part.startsWith(':')) {
          params[part.slice(1)] = decodeURIComponent(segments[i]);
        } else if (part !== segments[i]) {
          ok = false;
          break;
        }
      }
      if (!ok) continue;
      if (route.method !== method.toUpperCase() && !(route.method === 'GET' && method === 'HEAD')) {
        methodMismatch = true;
        continue;
      }
      return { route, params };
    }
    if (methodMismatch) throw new HttpError(405, 'method not allowed');
    return null;
  }
}

/** Simple fixed-window rate limiter for auth endpoints. */
class RateLimiter {
  constructor({ max = 10, windowMs = 60000 } = {}) {
    this.max = max;
    this.windowMs = windowMs;
    this.buckets = new Map();
  }

  check(key) {
    const now = Date.now();
    let bucket = this.buckets.get(key);
    if (!bucket || now > bucket.resetAt) {
      bucket = { count: 0, resetAt: now + this.windowMs };
      this.buckets.set(key, bucket);
    }
    bucket.count++;
    if (this.buckets.size > 5000) {
      for (const [k, v] of this.buckets) {
        if (now > v.resetAt) this.buckets.delete(k);
      }
    }
    return { allowed: bucket.count <= this.max, remaining: Math.max(0, this.max - bucket.count) };
  }

  reset(key) {
    this.buckets.delete(key);
  }
}

function parseUrl(req) {
  const host = req.headers.host || 'localhost';
  return new URL(req.url, `http://${host}`);
}

module.exports = {
  HttpError,
  Router,
  Session,
  RateLimiter,
  sendJson,
  sendText,
  sendError,
  readBody,
  readJson,
  parseCookies,
  clientIp,
  parseUrl,
  MIME,
};
