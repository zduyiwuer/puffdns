'use strict';

const { TYPE, TYPE_NAME, CLASS_IN, EDNS } = require('./types');

// ---------------------------------------------------------------------------
// Domain name helpers
// ---------------------------------------------------------------------------

/** Normalize a domain name to lowercase without trailing dot. Root becomes "". */
function normalizeName(name) {
  if (name === undefined || name === null) return '';
  let n = String(name).trim().toLowerCase();
  while (n.endsWith('.')) n = n.slice(0, -1);
  return n;
}

/** Split a normalized name into labels. Root -> []. */
function toLabels(name) {
  const n = normalizeName(name);
  if (!n) return [];
  return n.split('.').filter((l) => l.length > 0);
}

/** Number of labels, used for wildcard matching. */
function labelCount(name) {
  return toLabels(name).length;
}

/** True when the name is inside zone (including equal). */
function isSubdomain(name, zone) {
  const n = normalizeName(name);
  const z = normalizeName(zone);
  if (!z) return true;
  if (n === z) return true;
  return n.endsWith('.' + z);
}

/** Get the parent zone of a name, one label up. */
function parentZone(name) {
  const labels = toLabels(name);
  if (labels.length <= 1) return '';
  return labels.slice(1).join('.');
}

const MAX_NAME_LENGTH = 255;
const MAX_LABEL_LENGTH = 63;

// ---------------------------------------------------------------------------
// IP helpers
// ---------------------------------------------------------------------------

function parseIPv4(str) {
  const parts = String(str).trim().split('.');
  if (parts.length !== 4) return null;
  const bytes = [];
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n < 0 || n > 255) return null;
    bytes.push(n);
  }
  return bytes;
}

function isIPv4(str) {
  return parseIPv4(str) !== null;
}

/** Expand an IPv6 string (including "::" and IPv4-mapped forms) to 16 bytes. */
function parseIPv6(str) {
  let s = String(str).trim();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  if (!s.includes(':')) return null;

  // Handle embedded IPv4 (e.g. ::ffff:1.2.3.4)
  const lastColon = s.lastIndexOf(':');
  const tail = s.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4Bytes = parseIPv4(tail);
    if (!v4Bytes) return null;
    // Replace the dotted quad with two hex groups, keeping the leading colon
    const g1 = ((v4Bytes[0] << 8) | v4Bytes[1]).toString(16);
    const g2 = ((v4Bytes[2] << 8) | v4Bytes[3]).toString(16);
    s = `${s.slice(0, lastColon + 1)}${g1}:${g2}`;
  }

  const doubleColon = s.indexOf('::');
  let groups;
  if (doubleColon >= 0) {
    const left = s.slice(0, doubleColon);
    const right = s.slice(doubleColon + 2);
    const leftParts = left.length ? left.split(':') : [];
    const rightParts = right.length ? right.split(':') : [];
    const fill = 8 - leftParts.length - rightParts.length;
    if (fill < 0) return null;
    groups = [...leftParts, ...new Array(fill).fill('0'), ...rightParts];
  } else {
    groups = s.split(':');
  }
  if (groups.length !== 8) return null;

  const bytes = [];
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    const v = parseInt(g, 16);
    bytes.push((v >> 8) & 0xff, v & 0xff);
  }
  return bytes;
}

function isIPv6(str) {
  return parseIPv6(str) !== null;
}

function isIP(str) {
  return isIPv4(str) || isIPv6(str);
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

class Reader {
  constructor(buf) {
    this.buf = buf;
    this.offset = 0;
  }
  get remaining() {
    return this.buf.length - this.offset;
  }
  u8() {
    if (this.remaining < 1) throw new Error('unexpected end of DNS message');
    return this.buf[this.offset++];
  }
  u16() {
    if (this.remaining < 2) throw new Error('unexpected end of DNS message');
    const v = this.buf.readUInt16BE(this.offset);
    this.offset += 2;
    return v;
  }
  u32() {
    if (this.remaining < 4) throw new Error('unexpected end of DNS message');
    const v = this.buf.readUInt32BE(this.offset);
    this.offset += 4;
    return v;
  }
  bytes(n) {
    if (this.remaining < n) throw new Error('unexpected end of DNS message');
    const b = this.buf.subarray(this.offset, this.offset + n);
    this.offset += n;
    return b;
  }
  /**
   * Read a domain name, following compression pointers.
   * Returns { name, offset, nextOffset } where offset is where the name
   * started and nextOffset is where reading should continue.
   *
   * Pass `limit` when reading inside RDATA: compression pointers must be
   * refused there, because a pointer target outside the record would be
   * ambiguous and could make a malformed record derail the whole parse.
   */
  name(limit) {
    const start = this.offset;
    const labels = [];
    let nextOffset = null;
    let jumps = 0;
    let total = 0;

    while (true) {
      if (this.remaining < 1) throw new Error('unexpected end of name');
      const len = this.buf[this.offset];

      if (len === 0) {
        this.offset += 1;
        if (nextOffset === null) nextOffset = this.offset;
        break;
      }

      if ((len & 0xc0) === 0xc0) {
        // Compression pointer
        if (limit !== undefined) throw new Error('compression pointer not allowed here');
        if (this.remaining < 2) throw new Error('bad compression pointer');
        const ptr = ((len & 0x3f) << 8) | this.buf[this.offset + 1];
        if (nextOffset === null) nextOffset = this.offset + 2;
        if (ptr >= this.offset) throw new Error('forward compression pointer');
        this.offset = ptr;
        if (++jumps > 64) throw new Error('too many compression pointers');
        continue;
      }

      if ((len & 0xc0) !== 0) throw new Error('unknown label type');
      if (len > MAX_LABEL_LENGTH) throw new Error('label too long');
      if (this.remaining < len + 1) throw new Error('unexpected end of label');

      total += len + 1;
      if (total > MAX_NAME_LENGTH) throw new Error('name too long');
      labels.push(this.buf.toString('utf8', this.offset + 1, this.offset + 1 + len));
      this.offset += len + 1;
    }

    // Reading may have jumped elsewhere via compression pointers; the caller's
    // stream position is always the byte right after the encoded name.
    this.offset = nextOffset;
    return { name: labels.join('.').toLowerCase(), offset: start, nextOffset };
  }
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

class Writer {
  constructor(initial = 512) {
    this.buf = Buffer.alloc(initial);
    this.offset = 0;
  }
  _ensure(n) {
    if (this.offset + n <= this.buf.length) return;
    let size = this.buf.length * 2 || 512;
    while (size < this.offset + n) size *= 2;
    const next = Buffer.alloc(size);
    this.buf.copy(next, 0, 0, this.offset);
    this.buf = next;
  }
  u8(v) {
    this._ensure(1);
    this.buf[this.offset++] = v & 0xff;
  }
  u16(v) {
    this._ensure(2);
    this.buf.writeUInt16BE(v & 0xffff, this.offset);
    this.offset += 2;
  }
  u32(v) {
    this._ensure(4);
    this.buf.writeUInt32BE(v >>> 0, this.offset);
    this.offset += 4;
  }
  bytes(b) {
    this._ensure(b.length);
    b.copy(this.buf, this.offset);
    this.offset += b.length;
  }
  /** Write a name, using compression pointers when the suffix is known. */
  name(name, compression) {
    const labels = toLabels(name);
    for (let i = 0; i < labels.length; i++) {
      const suffix = labels.slice(i).join('.').toLowerCase();
      if (compression && compression.has(suffix)) {
        const ptr = compression.get(suffix);
        this.u16(0xc000 | ptr);
        return;
      }
      if (compression && this.offset < 0x4000) {
        compression.set(suffix, this.offset);
      }
      const label = Buffer.from(labels[i], 'utf8');
      if (label.length > MAX_LABEL_LENGTH) throw new Error('label too long');
      this.u8(label.length);
      this.bytes(label);
    }
    this.u8(0);
  }
  result() {
    return this.buf.subarray(0, this.offset);
  }
  get length() {
    return this.offset;
  }
}

// ---------------------------------------------------------------------------
// RDATA
// ---------------------------------------------------------------------------

function encodeIPv4(str) {
  const b = parseIPv4(str);
  if (!b) throw new Error(`invalid IPv4 address: ${str}`);
  return Buffer.from(b);
}

function encodeIPv6(str) {
  const b = parseIPv6(str);
  if (!b) throw new Error(`invalid IPv6 address: ${str}`);
  return Buffer.from(b);
}

function encodeNameRdata(name) {
  const w = new Writer(64);
  w.name(name);
  return Buffer.from(w.result());
}

/** Split a long TXT string into <=255 byte character-strings. */
function encodeTxtStrings(text) {
  const raw = Buffer.from(String(text), 'utf8');
  const parts = [];
  for (let i = 0; i < raw.length || i === 0; i += 255) {
    parts.push(raw.subarray(i, Math.min(i + 255, raw.length)));
    if (raw.length === 0) break;
  }
  const w = new Writer(raw.length + 32);
  for (const p of parts) {
    w.u8(p.length);
    w.bytes(p);
  }
  if (!parts.length) w.u8(0);
  return Buffer.from(w.result());
}

/**
 * RDATA is always encoded WITHOUT compression pointers.
 *
 * This is not a limitation but a requirement of RFC 1035 §4.1.4: a receiver
 * must be able to decompress a name inside RDATA knowing only that RDATA's
 * own offset, which is impossible for a pointer that targets elsewhere in the
 * message. Compressing here would also make the RDLENGTH depend on the
 * surrounding message, so records could not be cached or copied in isolation.
 */
function encodeRdata(rr, _compression) {
  const t = rr.type;
  const data = rr.data === undefined || rr.data === null ? '' : String(rr.data);

  switch (t) {
    case TYPE.A:
      return encodeIPv4(data.trim());
    case TYPE.AAAA:
      return encodeIPv6(data.trim());
    case TYPE.NS:
    case TYPE.CNAME:
    case TYPE.PTR:
    case TYPE.DNAME:
      return encodeNameRdata(normalizeName(data.trim()));
    case TYPE.MX: {
      const parts = data.trim().split(/\s+/);
      const pref = parseInt(parts[0], 10);
      if (!Number.isFinite(pref)) throw new Error('MX requires a numeric preference');
      const exchange = normalizeName(parts[1] || '');
      if (!exchange) throw new Error('MX requires an exchange host');
      const w = new Writer(64);
      w.u16(pref);
      w.name(exchange);
      return Buffer.from(w.result());
    }
    case TYPE.SRV: {
      const parts = data.trim().split(/\s+/);
      if (parts.length < 4) throw new Error('SRV requires "priority weight port target"');
      const w = new Writer(96);
      w.u16(parseInt(parts[0], 10) || 0);
      w.u16(parseInt(parts[1], 10) || 0);
      w.u16(parseInt(parts[2], 10) || 0);
      w.name(normalizeName(parts.slice(3).join(' ')));
      return Buffer.from(w.result());
    }
    case TYPE.TXT:
    case TYPE.SPF: {
      // Only treat the value as several strings when it is actually quoted;
      // otherwise the whole thing (spaces included) is one character-string.
      const trimmed = data.trim();
      if (trimmed.startsWith('"')) {
        const parts = parseQuotedStrings(data);
        const w = new Writer(512);
        for (const p of parts) w.bytes(encodeTxtStrings(p));
        return Buffer.from(w.result());
      }
      return encodeTxtStrings(data);
    }
    case TYPE.SOA: {
      const parts = data.trim().split(/\s+/);
      if (parts.length < 7) throw new Error('SOA requires 7 fields');
      const w = new Writer(256);
      w.name(normalizeName(parts[0]));
      w.name(normalizeName(parts[1]));
      w.u32(Number(parts[2]) >>> 0);
      w.u32(Number(parts[3]) >>> 0);
      w.u32(Number(parts[4]) >>> 0);
      w.u32(Number(parts[5]) >>> 0);
      w.u32(Number(parts[6]) >>> 0);
      return Buffer.from(w.result());
    }
    case TYPE.CAA: {
      const parts = data.trim().split(/\s+/);
      if (parts.length < 3) throw new Error('CAA requires "flags tag value"');
      const w = new Writer(256);
      w.u8(parseInt(parts[0], 10) || 0);
      const tag = parts[1];
      w.u8(tag.length);
      w.bytes(Buffer.from(tag, 'utf8'));
      w.bytes(Buffer.from(parts.slice(2).join(' '), 'utf8'));
      return Buffer.from(w.result());
    }
    case TYPE.HINFO: {
      const parts = parseQuotedStrings(data);
      const cpu = parts[0] || '';
      const os = parts[1] || '';
      const w = new Writer(128);
      for (const s of [cpu, os]) {
        const b = Buffer.from(s, 'utf8').subarray(0, 255);
        w.u8(b.length);
        w.bytes(b);
      }
      return Buffer.from(w.result());
    }
    default:
      // Unknown type: store as-is using the TXT representation on the wire is
      // wrong, so refuse rather than emit garbage.
      throw new Error(`unsupported record type: ${TYPE_NAME[t] || t}`);
  }
}

function parseQuotedStrings(data) {
  const out = [];
  const re = /"((?:[^"\\]|\\.)*)"|(\S+)/g;
  let m;
  while ((m = re.exec(String(data))) !== null) {
    if (m[1] !== undefined) out.push(m[1].replace(/\\(.)/g, '$1'));
    else out.push(m[2]);
  }
  return out;
}

function decodeRdata(type, rdata) {
  const r = new Reader(rdata);
  switch (type) {
    case TYPE.A: {
      const b = r.bytes(4);
      return `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
    }
    case TYPE.AAAA: {
      const b = r.bytes(16);
      const groups = [];
      for (let i = 0; i < 16; i += 2) groups.push(((b[i] << 8) | b[i + 1]).toString(16));
      // Prefer the compressed form for readability
      let best = groups.join(':');
      let bestLen = best.length;
      for (let i = 0; i < 8; i++) {
        for (let j = i + 1; j <= 8; j++) {
          const isZero = groups.slice(i, j).every((g) => g === '0');
          if (!isZero) continue;
          const candidate = groups.slice(0, i).join(':') + '::' + groups.slice(j).join(':');
          if (candidate.length < bestLen) {
            bestLen = candidate.length;
            best = candidate;
          }
        }
      }
      return best;
    }
    case TYPE.NS:
    case TYPE.CNAME:
    case TYPE.PTR:
    case TYPE.DNAME:
      return r.name().name;
    case TYPE.MX: {
      const pref = r.u16();
      const ex = r.name().name;
      return `${pref} ${ex}`;
    }
    case TYPE.SRV: {
      const p = r.u16();
      const w = r.u16();
      const port = r.u16();
      const target = r.name().name;
      return `${p} ${w} ${port} ${target || '.'}`;
    }
    case TYPE.TXT:
    case TYPE.SPF: {
      const parts = [];
      while (r.remaining > 0) {
        const len = r.u8();
        parts.push(r.bytes(len).toString('utf8'));
      }
      // A record that had a single string round-trips to itself; one that was
      // chunked is rejoined so the displayed value stays readable.
      return parts.join('');
    }
    case TYPE.SOA: {
      const mname = r.name().name;
      const rname = r.name().name;
      return `${mname} ${rname} ${r.u32()} ${r.u32()} ${r.u32()} ${r.u32()} ${r.u32()}`;
    }
    case TYPE.CAA: {
      r.u8();
      const tagLen = r.u8();
      const tag = r.bytes(tagLen).toString('utf8');
      return `${tag} ${r.remaining ? r.bytes(r.remaining).toString('utf8') : ''}`;
    }
    case TYPE.HINFO: {
      const l1 = r.u8();
      const cpu = r.bytes(l1).toString('utf8');
      if (r.remaining === 0) return `"${cpu}"`;
      const l2 = r.u8();
      return `"${cpu}" "${r.bytes(l2).toString('utf8')}"`;
    }
    default: {
      const hex = Buffer.from(rdata).toString('hex').toUpperCase();
      return `\\# ${rdata.length} ${hex}`;
    }
  }
}

// ---------------------------------------------------------------------------
// Message decode / encode
// ---------------------------------------------------------------------------

function decodeMessage(buf) {
  const r = new Reader(buf);
  const id = r.u16();
  const flags = r.u16();
  const counts = { qd: r.u16(), an: r.u16(), ns: r.u16(), ar: r.u16() };

  const questions = [];
  for (let i = 0; i < counts.qd; i++) {
    const n = r.name();
    const qtype = r.u16();
    const qclass = r.u16();
    questions.push({ name: n.name, type: qtype, class: qclass });
  }

  const readSection = (count) => {
    const out = [];
    for (let i = 0; i < count; i++) {
      const n = r.name();
      const type = r.u16();
      const cls = r.u16();
      const ttl = r.u32();
      const rdlength = r.u16();
      const start = r.offset;
      const raw = r.bytes(rdlength);
      const rr = {
        name: n.name,
        type,
        class: cls,
        ttl,
        data: '',
      };
      if (type === TYPE.OPT) {
        rr.opt = parseOpt(raw, ttl, cls);
      } else {
        try {
          rr.data = decodeRdata(type, raw);
        } catch {
          rr.data = `\\# ${rdlength} ${raw.toString('hex').toUpperCase()}`;
        }
      }
      rr.rdataStart = start;
      out.push(rr);
    }
    return out;
  };

  const answers = readSection(counts.an);
  const authority = readSection(counts.ns);
  const additionals = readSection(counts.ar);

  return {
    id,
    flags,
    questions,
    answers,
    authority,
    additionals,
    edns: parseEdns(additionals),
  };
}

function parseEdns(additionals) {
  const opt = additionals.find((rr) => rr.type === TYPE.OPT);
  if (!opt) return null;
  // EDNS info is carried in the OPT pseudo-RR itself: class = UDP payload
  // size, TTL = extended rcode | version | flags (DO bit is the top bit).
  return {
    udpPayloadSize: opt.class,
    version: (opt.ttl >>> 16) & 0xff,
    flags: opt.ttl & 0xffff,
    extendedRcode: (opt.ttl >>> 24) & 0xff,
    options: opt.opt ? opt.opt.options : [],
    do: !!(opt.ttl & 0x8000),
  };
}

function parseOpt(raw) {
  const r = new Reader(raw);
  const options = [];
  try {
    while (r.remaining > 0) {
      const code = r.u16();
      const len = r.u16();
      const data = Buffer.from(r.bytes(len));
      options.push({ code, data });
    }
  } catch {
    /* malformed option block - ignore the rest */
  }
  return { options };
}

/** Build an OPT pseudo-record for the additional section. */
function buildOpt({ udpPayloadSize = 4096, doBit = false, version = 0, extendedRcode = 0, options = [] } = {}) {
  const w = new Writer(256);
  for (const o of options) {
    w.u16(o.code);
    w.u16(o.data.length);
    w.bytes(o.data);
  }
  const ttl = ((extendedRcode & 0xff) << 24) | ((version & 0xff) << 16) | (doBit ? 0x8000 : 0);
  return {
    name: '',
    type: TYPE.OPT,
    class: udpPayloadSize,
    ttl: ttl >>> 0,
    rdata: Buffer.from(w.result()),
  };
}

/**
 * Encode a full DNS message.
 * msg: { id, flags, questions, answers, authority, additionals }
 */
function encodeMessage(msg) {
  const w = new Writer(512);
  const compression = new Map();

  const questions = msg.questions || [];
  const answers = msg.answers || [];
  const authority = msg.authority || [];
  const additionals = msg.additionals || [];

  w.u16(msg.id || 0);
  w.u16(msg.flags || 0);
  w.u16(questions.length);
  w.u16(answers.length);
  w.u16(authority.length);
  w.u16(additionals.length);

  for (const q of questions) {
    w.name(q.name, compression);
    w.u16(q.type);
    w.u16(q.class || CLASS_IN);
  }

  const writeSection = (section) => {
    for (const rr of section) {
      w.name(rr.name || '', compression);
      w.u16(rr.type);
      w.u16(rr.class || CLASS_IN);
      w.u32(rr.ttl === undefined ? 3600 : rr.ttl);
      if (rr.type === TYPE.OPT && rr.rdata) {
        w.u16(rr.rdata.length);
        w.bytes(rr.rdata);
      } else {
        // RDATA is self-contained: see encodeRdata for why it is not compressed.
        const rdata = rr._rdata || encodeRdata(rr);
        w.u16(rdata.length);
        w.bytes(rdata);
      }
    }
  };

  writeSection(answers);
  writeSection(authority);
  writeSection(additionals);

  return Buffer.from(w.result());
}

/** Split a TCP DNS message (2-byte length prefix) into the raw payload. */
function decodeTcpMessage(buf) {
  if (buf.length < 2) return null;
  const len = buf.readUInt16BE(0);
  if (buf.length < len + 2) return null;
  return buf.subarray(2, len + 2);
}

/** Add a 2-byte length prefix for TCP transport. */
function encodeTcpMessage(buf) {
  const out = Buffer.alloc(buf.length + 2);
  out.writeUInt16BE(buf.length, 0);
  buf.copy(out, 2);
  return out;
}

function makeFlags({ qr, opcode, aa, tc, rd, ra, ad, cd, rcode }) {
  let f = 0;
  if (qr) f |= 0x8000;
  if (opcode) f |= (opcode & 0x0f) << 11;
  if (aa) f |= 0x0400;
  if (tc) f |= 0x0200;
  if (rd) f |= 0x0100;
  if (ra) f |= 0x0080;
  if (ad) f |= 0x0020;
  if (cd) f |= 0x0010;
  if (rcode) f |= rcode & 0x0f;
  return f;
}

module.exports = {
  Reader,
  Writer,
  normalizeName,
  toLabels,
  labelCount,
  isSubdomain,
  parentZone,
  parseIPv4,
  parseIPv6,
  isIPv4,
  isIPv6,
  isIP,
  encodeMessage,
  decodeMessage,
  decodeTcpMessage,
  encodeTcpMessage,
  makeFlags,
  buildOpt,
  decodeRdata,
  encodeRdata,
  parseQuotedStrings,
  MAX_NAME_LENGTH,
  MAX_LABEL_LENGTH,
  TYPE,
  EDNS,
};
