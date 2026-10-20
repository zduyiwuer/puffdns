'use strict';

const dgram = require('dgram');
const net = require('net');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const log = require('../util/log');
const {
  decodeMessage,
  encodeMessage,
  encodeTcpMessage,
  decodeTcpMessage,
  makeFlags,
  isIPv4,
} = require('./packet');

const DEFAULT_UPSTREAMS = [
  { host: '1.1.1.1', port: 53, proto: 'udp' },
  { host: '8.8.8.8', port: 53, proto: 'udp' },
  { host: '9.9.9.9', port: 53, proto: 'udp' },
];

/**
 * Forwards queries to upstream resolvers over UDP (with TCP fallback on
 * truncation), racing them in parallel and using the first valid answer.
 */
class UpstreamResolver extends EventEmitter {
  constructor(options = {}) {
    super();
    // Always normalize: callers pass plain strings ("1.1.1.1") from env vars
    // and objects from the settings API, but the query path needs
    // {host, port, proto} for every entry.
    this.upstreams = normalizeUpstreams(options.upstreams);
    this.timeout = options.timeout || 3000;
    this.maxParallel = options.maxParallel || 2;
    this.maxAttempts = options.maxAttempts || 3;
    this.tcpFallback = options.tcpFallback !== false;
    this.sockets = new Map();
    this.pending = new Map(); // key -> { resolve, reject }
    this._idSeq = crypto.randomInt(1, 0xffff);
    this.stats = { queries: 0, udpQueries: 0, tcpQueries: 0, failures: 0, timeouts: 0 };
    this._closed = false;
  }

  setUpstreams(list) {
    const parsed = normalizeUpstreams(list);
    this.upstreams = parsed;
    log.info('upstream resolvers updated', parsed.map((u) => `${u.host}:${u.port}/${u.proto}`).join(', '));
    return parsed;
  }

  _makeSocket(family) {
    const key = family || 'udp4';
    if (this.sockets.has(key)) return this.sockets.get(key);
    const socket = dgram.createSocket({ type: key, reuseAddr: true });
    socket.on('message', (msg, rinfo) => this._onMessage(msg, rinfo));
    socket.on('error', (err) => {
      log.warn('upstream socket error', err.message);
      // A socket-level failure (typically ECONNREFUSED surfaced as an ICMP
      // error on some platforms) invalidates every query in flight on it.
      // Reject them now instead of letting each one wait out its full timer.
      if (err.code === 'ECONNREFUSED' || err.code === 'EHOSTUNREACH' || err.code === 'ENETUNREACH') {
        for (const entry of [...this.pending.values()]) {
          entry.reject(new Error(`upstream unreachable: ${err.code}`));
        }
      }
    });
    socket.bind(() => {
      try {
        socket.setBroadcast(false);
      } catch {
        /* not supported everywhere; harmless */
      }
    });
    this.sockets.set(key, socket);
    return socket;
  }

  _onMessage(msg, rinfo) {
    if (msg.length < 12) return;
    const id = msg.readUInt16BE(0);
    const key = `${rinfo.address}:${rinfo.port}:${id}`;
    const entry = this.pending.get(key);
    if (!entry) return;

    let decoded = null;
    try {
      decoded = decodeMessage(msg);
    } catch (err) {
      entry.reject(new Error(`malformed upstream response: ${err.message}`));
      return;
    }
    entry.resolve({ msg, decoded, rinfo });
  }

  /**
   * Send a raw DNS message (without TCP prefix) to one upstream over UDP.
   *
   * The pending entry is keyed by upstream, port and query ID, so an
   * in-flight query can only be completed by a reply carrying that exact ID
   * from that exact address. The key is cleared on every exit path.
   */
  _queryUdpOnce(upstream, queryBuf) {
    return new Promise((resolve, reject) => {
      const family = isIPv4(upstream.host) ? 'udp4' : 'udp6';
      const socket = this._makeSocket(family);
      const key = `${upstream.host}:${upstream.port}:${queryBuf.readUInt16BE(0)}`;

      let settled = false;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        // Only remove our own entry: a duplicate key must not evict someone else.
        if (this.pending.get(key) === entry) this.pending.delete(key);
        fn(value);
      };

      const timer = setTimeout(() => {
        this.stats.timeouts++;
        finish(reject, new Error('upstream timeout'));
      }, this.timeout);
      if (timer.unref) timer.unref();

      const entry = {
        resolve: (v) => finish(resolve, v),
        reject: (e) => finish(reject, e),
      };
      this.pending.set(key, entry);

      socket.send(queryBuf, 0, queryBuf.length, upstream.port, upstream.host, (err) => {
        if (err) finish(reject, err);
        else this.stats.udpQueries++;
      });
    });
  }

  _queryTcpOnce(upstream, queryBuf) {
    return new Promise((resolve, reject) => {
      const isV4 = isIPv4(upstream.host);
      const socket = net.connect({ host: upstream.host, port: upstream.port, family: isV4 ? 4 : 6 });
      let done = false;
      let buf = Buffer.alloc(0);

      const finish = (err, value) => {
        if (done) return;
        done = true;
        socket.removeAllListeners();
        socket.destroy();
        if (err) reject(err);
        else resolve(value);
      };

      socket.setTimeout(this.timeout, () => {
        this.stats.timeouts++;
        finish(new Error('upstream tcp timeout'));
      });
      socket.on('error', (err) => finish(err));
      socket.on('connect', () => {
        socket.write(encodeTcpMessage(queryBuf));
        this.stats.tcpQueries++;
      });
      socket.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        const msg = decodeTcpMessage(buf);
        if (msg) {
          let decoded = null;
          try {
            decoded = decodeMessage(msg);
          } catch (err) {
            return finish(new Error(`malformed tcp response: ${err.message}`));
          }
          finish(null, { msg, decoded, rinfo: { address: upstream.host, port: upstream.port } });
        } else if (buf.length > 65535) {
          finish(new Error('tcp response too large'));
        }
      });
    });
  }

  /**
   * Give each outgoing query a fresh ID.
   *
   * Two jobs are at once. The 16-bit ID must change per request so a late or
   * spoofed reply cannot be mistaken for the answer to a different question.
   * But the ID is also half of the pending-map key, and a plain increment can
   * repeat a value that is still in flight — the new request would then evict
   * the older one's entry and the older one would hang until its timer fired.
   * Seeding from a random start keeps the sequence unpredictable; the map is
   * keyed by host, port and ID, so a collision only matters within one upstream.
   */
  _nextQueryId() {
    this._idSeq = ((this._idSeq || crypto.randomInt(1, 0xffff)) + 0x1021) & 0xffff;
    if (this._idSeq === 0) this._idSeq = 1;
    return this._idSeq;
  }

  _rewriteId(queryBuf) {
    const out = Buffer.from(queryBuf);
    out.writeUInt16BE(this._nextQueryId(), 0);
    return out;
  }

  /**
   * Resolve a query against upstreams.
   * queryBuf is a raw DNS message; returns { msg, decoded, upstream }.
   */
  async resolve(queryBuf, { preferTcp = false } = {}) {
    if (this._closed) throw new Error('resolver closed');
    this.stats.queries++;
    let lastErr = null;

    // Rotate the starting upstream per attempt so a dead one is skipped on
    // the first try rather than after a full timeout. This keeps a partial
    // outage from slowing every query.
    const pool = this.upstreams;
    const offset = this.stats.queries % Math.max(1, pool.length);

    for (let attempt = 0; attempt < this.maxAttempts; attempt++) {
      const batch = [];
      for (let k = 0; k < this.maxParallel; k++) {
        const idx = (offset + attempt * this.maxParallel + k) % pool.length;
        const candidate = pool[idx];
        if (candidate && !batch.includes(candidate)) batch.push(candidate);
      }
      if (!batch.length) break;

      const race = batch.map((upstream) => {
        const q = this._rewriteId(queryBuf);
        const runner =
          preferTcp || upstream.proto === 'tcp' ? this._queryTcpOnce(upstream, q) : this._queryUdpOnce(upstream, q);
        return runner
          .then(async (res) => {
            // Truncated over UDP -> retry the same upstream over TCP
            const isTruncated = res.decoded && res.decoded.flags & 0x0200;
            if (isTruncated && this.tcpFallback && !(preferTcp || upstream.proto === 'tcp')) {
              try {
                return await this._queryTcpOnce(upstream, this._rewriteId(queryBuf));
              } catch {
                /* keep the truncated UDP answer as a last resort */
              }
            }
            return res;
          })
          .then((res) => ({ ...res, upstream }))
          .catch((err) => {
            lastErr = err;
            return null;
          });
      });

      const results = await Promise.all(race);
      const winner = results.find((r) => r && r.decoded && r.decoded.questions.length > 0);
      if (winner) return winner;
    }

    this.stats.failures++;
    throw lastErr || new Error('no upstream produced an answer');
  }

  close() {
    this._closed = true;
    for (const entry of this.pending.values()) {
      entry.reject(new Error('resolver closed'));
    }
    this.pending.clear();
    for (const socket of this.sockets.values()) {
      try {
        socket.close();
      } catch {
        /* already closed */
      }
    }
    this.sockets.clear();
  }

  getStats() {
    return { ...this.stats, upstreams: this.upstreams.length };
  }
}

function normalizeUpstreams(list) {
  if (!Array.isArray(list)) return DEFAULT_UPSTREAMS.slice();
  const out = [];
  for (const item of list) {
    if (!item) continue;
    if (typeof item === 'string') {
      const parsed = parseUpstreamString(item);
      if (parsed) out.push(parsed);
    } else if (typeof item === 'object' && item.host) {
      const parsed = parseUpstreamString(`${item.proto || 'udp'}://${item.host}:${item.port || 53}`);
      if (parsed) out.push(parsed);
    }
  }
  return out.length ? out : DEFAULT_UPSTREAMS.slice();
}

function parseUpstreamString(str) {
  const raw = String(str).trim();
  if (!raw) return null;
  let proto = 'udp';
  let rest = raw;
  if (rest.includes('://')) {
    const idx = rest.indexOf('://');
    proto = rest.slice(0, idx).toLowerCase();
    rest = rest.slice(idx + 3);
  }
  if (!['udp', 'tcp', 'dot'].includes(proto)) return null;
  let host = rest;
  let port = proto === 'dot' ? 853 : 53;
  if (rest.startsWith('[')) {
    const end = rest.indexOf(']');
    if (end < 0) return null;
    host = rest.slice(1, end);
    const tail = rest.slice(end + 1);
    if (tail.startsWith(':')) port = Number(tail.slice(1));
  } else if (rest.includes(':') && (rest.match(/:/g) || []).length === 1) {
    const [h, p] = rest.split(':');
    host = h;
    port = Number(p);
  } else if ((rest.match(/:/g) || []).length > 1) {
    host = rest; // bare IPv6 without brackets, default port
  }
  if (!host) return null;
  if (!Number.isFinite(port) || port <= 0 || port > 65535) port = proto === 'dot' ? 853 : 53;
  return { host, port, proto: proto === 'dot' ? 'tcp' : proto };
}

module.exports = { UpstreamResolver, normalizeUpstreams, parseUpstreamString, DEFAULT_UPSTREAMS, makeFlags, encodeMessage };
