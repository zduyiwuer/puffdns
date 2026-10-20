'use strict';

const dgram = require('dgram');
const net = require('net');
const { EventEmitter } = require('events');

const log = require('../util/log');
const { TYPE, RCODE, RCODE_NAME, FLAG, TYPE_NAME } = require('./types');
const {
  decodeMessage,
  encodeMessage,
  encodeTcpMessage,
  decodeTcpMessage,
  makeFlags,
  buildOpt,
  normalizeName,
  isIPv4,
  isIPv6,
} = require('./packet');
const { resolveCnameChain } = require('./zone');

const DEFAULT_UDP_SIZE = 512;
const MAX_UDP_SIZE = 4096;

/**
 * The DNS service front-end. Owns the UDP and TCP listeners and the query
 * pipeline: ACL -> authoritative zone -> forward to upstream.
 */
class DnsServer extends EventEmitter {
  constructor({ store, zoneEngine, upstream, cache, config, accessControl }) {
    super();
    this.store = store;
    this.zoneEngine = zoneEngine;
    this.upstream = upstream;
    this.cache = cache;
    this.config = config;
    this.accessControl = accessControl;

    this.udp4 = null;
    this.udp6 = null;
    this.tcp = null;
    this.udpPort = config.dnsPort;
    this.tcpPort = config.dnsPort;
    this.stats = {
      queries: 0,
      answered: 0,
      authoritative: 0,
      forwarded: 0,
      cached: 0,
      refused: 0,
      errors: 0,
      nxdomain: 0,
      truncated: 0,
    };
    this._closed = false;
  }

  // -------------------------------------------------------------------------
  // Listeners
  // -------------------------------------------------------------------------
  async listen() {
    const port = this.udpPort;

    await new Promise((resolve, reject) => {
      this.udp4 = dgram.createSocket({ type: 'udp4', reuseAddr: true });
      this.udp4.on('error', (err) => {
        if (err.code === 'EACCES' || err.code === 'EADDRINUSE') {
          log.error(
            `cannot bind UDP ${port} (${err.code}).\n` +
              '  Docker: run with NET_BIND_SERVICE or map the host port 53 to a high container port.\n' +
              '  Bare metal: grant CAP_NET_BIND_SERVICE, or set DNS_PORT to an unprivileged port.'
          );
          reject(err);
        } else {
          reject(err);
        }
      });
      this.udp4.on('message', (msg, rinfo) => this._onUdpMessage(msg, rinfo));
      this.udp4.bind(port, () => {
        log.info(`DNS listening on udp/4:${port}`);
        resolve();
      });
    });

    // IPv6 is best-effort: many container hosts have no v6
    try {
      await new Promise((resolve, reject) => {
        this.udp6 = dgram.createSocket({ type: 'udp6', reuseAddr: true });
        this.udp6.on('error', reject);
        this.udp6.on('message', (msg, rinfo) => this._onUdpMessage(msg, rinfo));
        this.udp6.bind(port, () => {
          log.info(`DNS listening on udp/6:${port}`);
          resolve();
        });
      });
    } catch (err) {
      log.warn(`IPv6 UDP listener disabled (${err.message})`);
      if (this.udp6) {
        try {
          this.udp6.close();
        } catch {
          /* ignore */
        }
        this.udp6 = null;
      }
    }

    await new Promise((resolve, reject) => {
      this.tcp = net.createServer((socket) => this._onTcpConnection(socket));
      this.tcp.on('error', (err) => {
        if (err.code === 'EACCES' || err.code === 'EADDRINUSE') {
          log.error(`cannot bind TCP ${this.tcpPort} (${err.code}). See the UDP hint above.`);
        }
        reject(err);
      });
      this.tcp.listen(this.tcpPort, () => {
        log.info(`DNS listening on tcp:${this.tcpPort}`);
        resolve();
      });
    });
  }

  async close() {
    this._closed = true;
    const closers = [];
    for (const sock of [this.udp4, this.udp6]) {
      if (!sock) continue;
      closers.push(new Promise((resolve) => sock.close(() => resolve())));
    }
    if (this.tcp) {
      closers.push(new Promise((resolve) => this.tcp.close(() => resolve())));
    }
    await Promise.all(closers);
  }

  // -------------------------------------------------------------------------
  // Transport handlers
  // -------------------------------------------------------------------------
  async _onUdpMessage(msg, rinfo) {
    let response;
    try {
      const query = this._parseQuery(msg);
      if (!query) return;
      response = await this._buildResponse(query.msg, {
        client: rinfo.address,
        family: 4,
        proto: 'udp',
        maxSize: query.msg.edns ? Math.min(query.msg.edns.udpPayloadSize || DEFAULT_UDP_SIZE, MAX_UDP_SIZE) : DEFAULT_UDP_SIZE,
      });
      if (response) {
        this.udp4.send(response, 0, response.length, rinfo.port, rinfo.address, () => {});
      }
    } catch (err) {
      log.warn(`udp query from ${rinfo.address} failed:`, err.message);
      this.stats.errors++;
    }
  }

  _onTcpConnection(socket) {
    socket.setTimeout(15000, () => socket.destroy());
    let buf = Buffer.alloc(0);

    socket.on('data', async (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      // A TCP DNS message is prefixed with its 2-byte length; handle pipelining
      while (buf.length >= 2) {
        const len = buf.readUInt16BE(0);
        if (buf.length < len + 2) break;
        const payload = buf.subarray(2, len + 2);
        buf = buf.subarray(len + 2);

        try {
          const query = this._parseQuery(payload);
          if (!query) continue;
          const response = await this._buildResponse(query.msg, {
            client: socket.remoteAddress,
            family: isIPv6(socket.remoteAddress) ? 6 : 4,
            proto: 'tcp',
            maxSize: 65535,
          });
          if (response) socket.write(encodeTcpMessage(response));
        } catch (err) {
          log.warn(`tcp query from ${socket.remoteAddress} failed:`, err.message);
          this.stats.errors++;
        }
      }
    });

    socket.on('error', () => socket.destroy());
    socket.on('close', () => socket.destroy());
  }

  _parseQuery(buf) {
    try {
      const msg = decodeMessage(buf);
      if (!msg.questions.length) return null;
      return { msg };
    } catch (err) {
      this.stats.errors++;
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // Query pipeline
  // -------------------------------------------------------------------------
  async _buildResponse(query, ctx) {
    this.stats.queries++;
    const started = Date.now();
    const question = query.questions[0];
    const qname = normalizeName(question.name);
    const qtype = question.type;
    const qclass = question.class;
    const wantsDnssec = !!(query.edns && query.edns.do);

    // Standard query only
    const opcode = (query.flags >> 11) & 0x0f;
    if (opcode !== 0) {
      return this._makeResponse(query, { rcode: RCODE.NOTIMP }, ctx);
    }

    if (!this.accessControl.isAllowed(ctx.client)) {
      this.stats.refused++;
      return this._makeResponse(query, { rcode: RCODE.REFUSED }, ctx);
    }

    // Only IN class is served
    if (qclass !== 1 && qclass !== 255) {
      return this._makeResponse(query, { rcode: RCODE.REFUSED }, ctx);
    }

    const logLine = {
      client: ctx.client,
      proto: ctx.proto,
      name: qname,
      type: TYPE_NAME[qtype] || qtype,
      ms: 0,
    };

    let result;
    try {
      result = await this._answer(query, ctx, { qname, qtype, wantsDnssec });
    } catch (err) {
      log.warn(`resolution error for ${qname}:`, err.message);
      this.stats.errors++;
      result = { rcode: RCODE.SERVFAIL, answers: [], authority: [], additionals: [] };
    }

    logLine.ms = Date.now() - started;
    logLine.rcode = RCODE_NAME[result.rcode] || result.rcode;
    logLine.source = result.source;
    logLine.count = (result.answers || []).length;
    this.emit('query', logLine);
    log.debug(
      `${ctx.client} ${ctx.proto} ${qname} ${TYPE_NAME[qtype] || qtype} -> ${logLine.rcode} ` +
        `${logLine.count}rr ${logLine.ms}ms (${result.source})`
    );

    this.stats.answered++;
    if (result.source === 'authoritative') this.stats.authoritative++;
    else if (result.source === 'cache') this.stats.cached++;
    else if (result.source === 'upstream') this.stats.forwarded++;
    if (result.rcode === RCODE.NXDOMAIN) this.stats.nxdomain++;

    return this._makeResponse(query, result, ctx);
  }

  async _answer(query, ctx, { qname, qtype, wantsDnssec }) {
    // 1) Authoritative zones take priority
    const zone = this.zoneEngine.findZone(qname);
    if (zone && !this.config.forwardOnly) {
      const result = this._answerAuthoritative(qname, qtype, zone);
      if (result) {
        return { ...result, source: 'authoritative' };
      }
    }

    // 2) Cache
    if (this.config.cacheEnabled && !wantsDnssec) {
      const hit = this.cache.get(qname, qtype);
      if (hit) {
        return { ...hit, source: 'cache' };
      }
    }

    // 3) Forward upstream
    const upstreamMsg = this._buildUpstreamQuery(query);
    try {
      const { decoded } = await this.upstream.resolve(upstreamMsg, {
        preferTcp: ctx.proto === 'tcp' && ctx.client && this._isLocalClient(ctx.client),
      });

      const ttl = computeMinTtl(decoded.answers, decoded.authority);
      const value = {
        rcode: decoded.flags & 0x0f,
        answers: decoded.answers.filter((rr) => rr.type !== TYPE.OPT),
        authority: decoded.authority.filter((rr) => rr.type !== TYPE.OPT),
        additionals: decoded.additionals.filter((rr) => rr.type !== TYPE.OPT),
      };

      if (this.config.cacheEnabled && !wantsDnssec) {
        this.cache.set(qname, qtype, value, ttl);
      }
      return { ...value, source: 'upstream' };
    } catch (err) {
      // Serve stale cache entries when upstream is unreachable
      if (this.config.serveStale) {
        const stale = this.cache.getStale ? this.cache.getStale(qname, qtype) : null;
        if (stale) return { ...stale, source: 'stale' };
      }
      return { rcode: RCODE.SERVFAIL, answers: [], authority: [], additionals: [], source: 'error', error: err.message };
    }
  }

  _answerAuthoritative(qname, qtype, zone) {
    // ANY query: return every record at the name
    if (qtype === TYPE.ANY) {
      const result = this.zoneEngine.lookup(qname, TYPE.A);
      const all = this.store.findRecords(zone, qname, null);
      if (all.length) {
        const cnames = this.store.findRecords(zone, qname, TYPE.CNAME);
        const rest = all.filter((r) => r.type !== TYPE.CNAME);
        return {
          rcode: RCODE.NOERROR,
          answers: [...rest, ...cnames].map((r) => this.zoneEngine.toRR(r)),
          authority: [],
          additionals: [],
        };
      }
      return this._nodataOrNx(qname, zone, result);
    }

    const result = this.zoneEngine.lookup(qname, qtype);
    if (!result) return null;

    if (result.cnameOnly && result.cnames.length) {
      const chain = resolveCnameChain(this.zoneEngine, zone, qname, qtype);
      return {
        rcode: RCODE.NOERROR,
        answers: [...chain.chain, ...chain.answers],
        authority: [],
        additionals: [],
      };
    }

    if (result.nxdomain) {
      return {
        rcode: RCODE.NXDOMAIN,
        answers: [],
        authority: result.extras || [],
        additionals: [],
      };
    }

    if (!result.answers.length) {
      // NODATA, but try the CNAME chain before giving up
      const chain = resolveCnameChain(this.zoneEngine, zone, qname, qtype);
      if (chain.chain.length) {
        return {
          rcode: RCODE.NOERROR,
          answers: [...chain.chain, ...chain.answers],
          authority: [],
          additionals: [],
        };
      }
      return {
        rcode: RCODE.NOERROR,
        answers: [],
        authority: result.extras || [],
        additionals: [],
      };
    }

    // Follow a CNAME if the answer set is only a CNAME
    const answers = result.answers;
    const onlyCname = answers.length === 1 && answers[0].type === TYPE.CNAME && qtype !== TYPE.CNAME;
    if (onlyCname) {
      const chain = resolveCnameChain(this.zoneEngine, zone, qname, qtype);
      return {
        rcode: RCODE.NOERROR,
        answers: [...chain.chain, ...chain.answers],
        authority: [],
        additionals: [],
      };
    }

    return {
      rcode: RCODE.NOERROR,
      answers,
      authority: result.extras || [],
      additionals: [],
    };
  }

  _nodataOrNx(qname, zone, result) {
    if (result && result.nxdomain) {
      return { rcode: RCODE.NXDOMAIN, answers: [], authority: result.extras || [], additionals: [] };
    }
    return { rcode: RCODE.NOERROR, answers: [], authority: (result && result.extras) || [], additionals: [] };
  }

  _buildUpstreamQuery(query) {
    // Send a clean query with EDNS0 so we get bigger answers
    const out = {
      id: query.id,
      flags: makeFlags({ qr: false, rd: true, opcode: 0 }),
      questions: query.questions.map((q) => ({ name: q.name, type: q.type, class: 1 })),
      answers: [],
      authority: [],
      additionals: [buildOpt({ udpPayloadSize: MAX_UDP_SIZE, doBit: !!(query.edns && query.edns.do) })],
    };
    return encodeMessage(out);
  }

  _isLocalClient(addr) {
    if (!addr) return false;
    const a = String(addr).replace(/^::ffff:/, '');
    return a === '127.0.0.1' || a === '::1' || a.startsWith('127.');
  }

  // -------------------------------------------------------------------------
  // Response encoding
  // -------------------------------------------------------------------------
  _makeResponse(query, result, ctx) {
    const question = query.questions[0];
    const rcode = result.rcode === undefined ? RCODE.NOERROR : result.rcode;
    const isAuthoritative = result.source === 'authoritative';

    const flags = makeFlags({
      qr: true,
      aa: isAuthoritative,
      rd: !!(query.flags & FLAG.RD),
      ra: true,
      ad: false,
      cd: !!(query.flags & FLAG.CD),
      rcode,
    });

    let answers = (result.answers || []).filter((rr) => rr.type !== TYPE.OPT);
    let authority = (result.authority || []).filter((rr) => rr.type !== TYPE.OPT);
    let additionals = (result.additionals || []).filter((rr) => rr.type !== TYPE.OPT);

    // Glue for in-zone NS / MX targets
    additionals = additionals.concat(this._addGlue(answers));

    const additionalsOut = [];
    if (query.edns) {
      additionalsOut.push(
        buildOpt({
          udpPayloadSize: ctx.maxSize,
          doBit: !!(query.edns.do),
          extendedRcode: 0,
        })
      );
    }

    const build = (a, ns, ar) =>
      encodeMessage({
        id: query.id,
        flags,
        questions: [{ name: question.name, type: question.type, class: question.class }],
        answers: a,
        authority: ns,
        additionals: ar,
      });

    let buf = build(answers, authority, additionalsOut.concat(additionals));

    // Truncate for UDP
    if (ctx.proto === 'udp' && buf.length > ctx.maxSize) {
      this.stats.truncated++;
      // First try dropping additional records, then the authority section
      let retry = build(answers, authority, additionalsOut);
      if (retry.length > ctx.maxSize) {
        // Drop answers one by one, keeping the TC bit set
        let a = answers.slice();
        while (a.length > 0 && build(a, [], additionalsOut).length > ctx.maxSize - 10) {
          a = a.slice(0, -1);
        }
        buf = encodeMessage({
          id: query.id,
          flags: flags | FLAG.TC,
          questions: [{ name: question.name, type: question.type, class: question.class }],
          answers: a,
          authority: [],
          additionals: additionalsOut,
        });
      } else {
        buf = retry;
      }
    }

    return buf;
  }

  _addGlue(answers) {
    if (!this.config.addGlue) return [];
    const out = [];
    const seen = new Set();
    for (const rr of answers) {
      let target = null;
      if (rr.type === TYPE.NS || rr.type === TYPE.MX || rr.type === TYPE.CNAME) {
        const parts = String(rr.data).trim().split(/\s+/);
        target = normalizeName(parts[parts.length - 1]);
      }
      if (!target || seen.has(target)) continue;
      const zone = this.zoneEngine.findZone(target);
      if (!zone) continue;
      const glue = this.store.findRecords(zone, target, TYPE.A);
      for (const g of glue) {
        out.push(this.zoneEngine.toRR(g));
        seen.add(target);
      }
    }
    return out;
  }

  getStats() {
    return { ...this.stats, cache: this.cache.stats(), upstream: this.upstream.getStats() };
  }
}

/** Smallest TTL across answer + authority RRs, clamped to [30, 86400]. */
function computeMinTtl(answers, authority) {
  let min = Infinity;
  for (const rr of [...(answers || []), ...(authority || [])]) {
    if (rr.type === TYPE.OPT) continue;
    if (rr.ttl < min) min = rr.ttl;
  }
  if (!Number.isFinite(min)) return 300;
  return Math.max(30, Math.min(min, 86400));
}

/** CIDR-based client allow/deny lists. */
class AccessControl {
  constructor(rules = []) {
    this.rules = rules;
  }

  setRules(rules) {
    this.rules = Array.isArray(rules) ? rules : [];
  }

  isAllowed(client) {
    if (!this.rules.length) return true;
    const addr = String(client || '').replace(/^::ffff:/, '');
    // A matching deny rule wins over allow rules
    let matchedAllow = false;
    for (const rule of this.rules) {
      if (!cidrMatch(addr, rule.cidr)) continue;
      if (String(rule.action).toLowerCase() === 'deny') return false;
      matchedAllow = true;
    }
    return matchedAllow;
  }
}

function cidrMatch(ip, cidr) {
  if (!cidr) return false;
  const target = normalizeIp(ip);
  const [range, bitsRaw] = String(cidr).split('/');
  const base = normalizeIp(range);
  if (!target || !base) return false;
  if (target.includes(':') !== base.includes(':')) return false;

  const bits = bitsRaw === undefined ? (base.includes(':') ? 128 : 32) : Number(bitsRaw);
  if (target.includes(':')) {
    return ipv6CidrMatch(target, base, bits);
  }
  return ipv4CidrMatch(target, base, bits);
}

function normalizeIp(ip) {
  const s = String(ip || '').replace(/^::ffff:/, '');
  if (isIPv4(s)) return s;
  if (isIPv6(s)) return s;
  return null;
}

function ipv4CidrMatch(ip, cidr, bits) {
  const a = ip.split('.').map(Number);
  const b = cidr.split('.').map(Number);
  if (bits <= 0) return true;
  const fullBytes = Math.floor(bits / 8);
  const remainder = bits % 8;
  for (let i = 0; i < fullBytes; i++) {
    if (a[i] !== b[i]) return false;
  }
  if (remainder > 0) {
    const mask = (0xff << (8 - remainder)) & 0xff;
    if ((a[fullBytes] & mask) !== (b[fullBytes] & mask)) return false;
  }
  return true;
}

function ipv6CidrMatch(ip, cidr, bits) {
  const expand = (s) => {
    const parts = s.split('::');
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts.length > 1 && parts[1] ? parts[1].split(':') : [];
    const fill = 8 - left.length - right.length;
    const groups = [...left, ...new Array(Math.max(0, fill)).fill('0'), ...right];
    const bytes = [];
    for (const g of groups.slice(0, 8)) {
      const v = parseInt(g || '0', 16) || 0;
      bytes.push((v >> 8) & 0xff, v & 0xff);
    }
    return bytes;
  };
  const a = expand(ip);
  const b = expand(cidr);
  const fullBytes = Math.floor(bits / 8);
  const remainder = bits % 8;
  for (let i = 0; i < fullBytes; i++) {
    if (a[i] !== b[i]) return false;
  }
  if (remainder > 0) {
    const mask = (0xff << (8 - remainder)) & 0xff;
    if ((a[fullBytes] & mask) !== (b[fullBytes] & mask)) return false;
  }
  return true;
}

module.exports = { DnsServer, AccessControl, cidrMatch, computeMinTtl };
