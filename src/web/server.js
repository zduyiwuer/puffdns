'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const log = require('../util/log');
const { MIME, sendJson, sendText, sendError, readBody, HttpError, parseUrl } = require('./http');
const { decodeMessage, encodeMessage, buildOpt } = require('../dns/packet');
const { RCODE, TYPE_NAME } = require('../dns/types');

const STATIC_DIR = path.join(__dirname, '..', '..', 'public');

/**
 * Web front-end: serves the single-page panel, the REST API, and a
 * DNS-over-HTTPS endpoint so the resolver can be used from browsers.
 */
function createWebServer({ apiRouter, store, config, dnsServer, cache, queryLog }) {
  const server = http.createServer(async (req, res) => {
    const started = Date.now();
    let url;
    try {
      url = parseUrl(req);
    } catch {
      return sendText(res, 400, 'bad request');
    }

    // Baseline security headers (the panel ships no inline scripts)
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'same-origin');

    try {
      // ---- DNS-over-HTTPS ----------------------------------------------
      if (url.pathname === '/dns-query') {
        return await handleDoh(req, res, url, { config, dnsServer, cache });
      }

      // ---- REST API -----------------------------------------------------
      if (url.pathname.startsWith('/api/')) {
        const match = apiRouter.match(req.method, url.pathname);
        if (!match) return sendJson(res, 404, { error: 'endpoint not found' });
        req.params = match.params;
        req.query = url.searchParams;
        req.url = url.pathname + url.search;
        await match.route.handler(req, res);
        return;
      }

      // ---- static panel --------------------------------------------------
      if (req.method === 'GET' || req.method === 'HEAD') {
        return serveStatic(url.pathname, res);
      }

      return sendText(res, 405, 'method not allowed');
    } catch (err) {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      sendError(res, err);
    } finally {
      const ms = Date.now() - started;
      if (ms > 1000) log.debug(`slow request ${req.method} ${url.pathname} ${ms}ms`);
    }
  });

  server.on('clientError', (err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });

  return server;
}

// ---------------------------------------------------------------------------
// DNS-over-HTTPS (RFC 8484)
// ---------------------------------------------------------------------------
async function handleDoh(req, res, url, { config, dnsServer }) {
  if (!config.dohEnabled) {
    return sendText(res, 404, 'DoH is disabled');
  }

  let queryBuf = null;

  if (req.method === 'GET') {
    const dnsParam = url.searchParams.get('dns');
    if (!dnsParam) return sendText(res, 400, 'missing ?dns= parameter');
    // base64url uses - and _ ; Buffer.from silently ignores invalid chars, so
    // validate the alphabet explicitly before decoding.
    if (!/^[A-Za-z0-9_-]+$/.test(dnsParam)) return sendText(res, 400, 'invalid base64url in ?dns=');
    queryBuf = Buffer.from(dnsParam, 'base64url');
  } else if (req.method === 'POST') {
    try {
      queryBuf = await readBody(req, 65535);
    } catch {
      return sendText(res, 413, 'request body too large');
    }
  } else {
    return sendText(res, 405, 'method not allowed');
  }

  if (!queryBuf || queryBuf.length < 12) return sendText(res, 400, 'malformed DNS message');

  let query;
  try {
    query = decodeMessage(queryBuf);
  } catch (err) {
    return sendText(res, 400, `malformed DNS query: ${err.message}`);
  }
  if (!query.questions.length) return sendText(res, 400, 'query has no question section');

  // Run the same pipeline the UDP/TCP listeners use
  const response = await dnsServer._buildResponse(query, {
    client: (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress,
    family: 4,
    proto: 'doh',
    maxSize: 65535,
  });

  const headers = {
    'Content-Type': 'application/dns-message',
    'Content-Length': response.length,
    'Cache-Control': 'max-age=60',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'content-type, accept',
  };
  res.writeHead(200, headers);
  res.end(response);
}

// ---------------------------------------------------------------------------
// Static files
// ---------------------------------------------------------------------------
function serveStatic(pathname, res) {
  let rel;
  try {
    rel = decodeURIComponent(pathname);
  } catch {
    return sendText(res, 400, 'malformed path');
  }
  if (rel === '/' || rel === '') rel = '/index.html';

  // Reject traversal on the *decoded* path. path.join alone is not enough:
  // it silently normalises ".." away, which would let a crafted path fall
  // through to the SPA fallback instead of being refused outright.
  if (rel.includes('\0') || rel.split(/[\\/]/).includes('..')) {
    return sendText(res, 403, 'forbidden');
  }

  const target = path.normalize(path.join(STATIC_DIR, rel));
  if (!target.startsWith(STATIC_DIR + path.sep) && target !== STATIC_DIR) {
    return sendText(res, 403, 'forbidden');
  }

  fs.stat(target, (err, stat) => {
    if (err || !stat.isFile()) {
      // Unknown paths without an extension fall back to the SPA shell; a
      // request that looks like a file should 404 instead of returning HTML.
      if (path.extname(rel)) return sendText(res, 404, 'not found');
      const index = path.join(STATIC_DIR, 'index.html');
      return fs.readFile(index, (e2, buf) => {
        if (e2) return sendText(res, 404, 'not found');
        res.writeHead(200, { 'Content-Type': MIME['.html'], 'Cache-Control': 'no-cache' });
        res.end(buf);
      });
    }
    const ext = path.extname(target).toLowerCase();
    const cacheControl = ext === '.html' ? 'no-cache' : 'public, max-age=3600';
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Content-Length': stat.size,
      'Cache-Control': cacheControl,
    });
    fs.createReadStream(target).pipe(res);
  });
}

module.exports = { createWebServer, STATIC_DIR };
