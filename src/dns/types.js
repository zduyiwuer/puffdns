'use strict';

// DNS record type codes
const TYPE = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  HINFO: 13,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  NAPTR: 35,
  CERT: 37,
  DNAME: 39,
  OPT: 41,
  DS: 43,
  SSHFP: 44,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  NSEC3: 50,
  TLSA: 52,
  SVCB: 64,
  HTTPS: 65,
  SPF: 99,
  CAA: 257,
  ANY: 255,
};

/**
 * Build the code -> name map explicitly rather than by iterating TYPE.
 * Iterating would let any duplicate numeric value silently win, and a
 * partially-populated map turns a valid type into "undefined" at runtime.
 */
const TYPE_NAME = {};
for (const [name, code] of Object.entries(TYPE)) {
  if (name === 'ANY' || name === 'OPT') continue;
  TYPE_NAME[code] = name;
}

const CLASS_IN = 1;
const CLASS_CH = 3;
const CLASS_HS = 4;
const CLASS_NONE = 254;
const CLASS_ANY = 255;

// Response codes
const RCODE = {
  NOERROR: 0,
  FORMERR: 1,
  SERVFAIL: 2,
  NXDOMAIN: 3,
  NOTIMP: 4,
  REFUSED: 5,
};

const RCODE_NAME = {};
for (const [name, code] of Object.entries(RCODE)) RCODE_NAME[code] = name;

// Opcodes
const OPCODE = { QUERY: 0, IQUERY: 1, STATUS: 2, NOTIFY: 4, UPDATE: 5 };

// EDNS0 option codes we care about
const EDNS = { NSID: 3, COOKIE: 10, TCP_KEEPALIVE: 11, PADDING: 12, NSID_ECHO: 65001 };

// Response flag bits
const FLAG = {
  QR: 0x8000, // response
  AA: 0x0400, // authoritative answer
  TC: 0x0200, // truncated
  RD: 0x0100, // recursion desired
  RA: 0x0080, // recursion available
  AD: 0x0020, // authentic data
  CD: 0x0010, // checking disabled
};

function typeToName(code) {
  return TYPE_NAME[code] || `TYPE${code}`;
}

function nameToType(name) {
  if (typeof name === 'number') return name;
  const upper = String(name || '').toUpperCase();
  if (upper in TYPE) return TYPE[upper];
  if (/^\d+$/.test(upper)) return Number(upper);
  return null;
}

const SUPPORTED_TYPES = [
  'A',
  'AAAA',
  'CNAME',
  'MX',
  'TXT',
  'NS',
  'SRV',
  'CAA',
  'PTR',
  'DNAME',
  'HINFO',
  'SPF',
];

// Types that may appear multiple times at the same owner name with the same
// value but different TTL — treated as "round robin" by resolvers.
const MULTI_OK = new Set(['A', 'AAAA', 'MX', 'NS', 'TXT', 'SRV', 'CAA', 'PTR']);

module.exports = {
  TYPE,
  TYPE_NAME,
  typeToName,
  nameToType,
  SUPPORTED_TYPES,
  MULTI_OK,
  CLASS_IN,
  CLASS_CH,
  CLASS_HS,
  CLASS_NONE,
  CLASS_ANY,
  RCODE,
  RCODE_NAME,
  OPCODE,
  EDNS,
  FLAG,
};
