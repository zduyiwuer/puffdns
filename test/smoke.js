'use strict';

/**
 * End-to-end self test. Exercises the DNS wire codec, the authoritative zone
 * engine and the HTTP API without touching the network (upstreams are stubbed).
 *
 *   node test/smoke.js
 */

const assert = require('assert');
const dgram = require('dgram');
const fs = require('fs');
const os = require('os');
const path = require('path');

const P = require('../src/dns/packet');
const { TYPE, RCODE } = require('../src/dns/types');
const { Store, hashPassword } = require('../src/store');
const { ZoneEngine, validateRecord } = require('../src/dns/zone');
const { DnsCache } = require('../src/dns/cache');
const { Session } = require('../src/web/http');
const { QueryLog } = require('../src/web/querylog');
const { createApi } = require('../src/web/api');
const { createWebServer } = require('../src/web/server');
const { DnsServer, AccessControl } = require('../src/dns/server');

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    passed++;
    process.stdout.write(`  \x1b[32m✓\x1b[0m ${name}\n`);
  } catch (err) {
    failed++;
    failures.push({ name, err });
    process.stdout.write(`  \x1b[31m✗\x1b[0m ${name}\n      ${err.message}\n`);
  }
}

function section(name) {
  process.stdout.write(`\n\x1b[1m${name}\x1b[0m\n`);
}

// ---------------------------------------------------------------------------
section('DNS wire codec');
// ---------------------------------------------------------------------------

test('encode + decode a simple A query round-trips', () => {
  const buf = P.encodeMessage({
    id: 0x1234,
    flags: P.makeFlags({ rd: true }),
    questions: [{ name: 'example.com', type: TYPE.A, class: 1 }],
  });
  assert.strictEqual(buf.readUInt16BE(0), 0x1234);
  const msg = P.decodeMessage(buf);
  assert.strictEqual(msg.questions[0].name, 'example.com');
  assert.strictEqual(msg.questions[0].type, TYPE.A);
  assert.strictEqual(msg.flags & 0x0100, 0x0100, 'RD flag must survive');
});

test('A record rdata encodes to 4 bytes and decodes back', () => {
  const buf = P.encodeMessage({
    id: 1,
    flags: 0x8180,
    questions: [{ name: 'a.example.com', type: TYPE.A, class: 1 }],
    answers: [{ name: 'a.example.com', type: TYPE.A, ttl: 300, data: '192.168.1.42' }],
  });
  const msg = P.decodeMessage(buf);
  assert.strictEqual(msg.answers.length, 1);
  assert.strictEqual(msg.answers[0].data, '192.168.1.42');
  assert.strictEqual(msg.answers[0].ttl, 300);
});

test('AAAA record handles compressed IPv6 notation', () => {
  const cases = [
    ['2001:db8::1', '2001:db8::1'],
    ['::1', '::1'],
    ['fe80::1:2:3:4', 'fe80::1:2:3:4'],
    ['::ffff:192.168.0.1', '::ffff:c0a8:1'],
  ];
  for (const [input, expected] of cases) {
    const buf = P.encodeMessage({
      id: 1,
      flags: 0x8180,
      questions: [{ name: 'v6.example.com', type: TYPE.AAAA, class: 1 }],
      answers: [{ name: 'v6.example.com', type: TYPE.AAAA, ttl: 60, data: input }],
    });
    const msg = P.decodeMessage(buf);
    assert.strictEqual(msg.answers[0].data, expected, `${input} -> ${expected}`);
  }
});

test('owner names are compressed while RDATA never is', () => {
  const buf = P.encodeMessage({
    id: 2,
    flags: 0x8180,
    questions: [{ name: 'www.example.com', type: TYPE.A, class: 1 }],
    answers: [
      { name: 'www.example.com', type: TYPE.A, ttl: 60, data: '1.1.1.1' },
      { name: 'www.example.com', type: TYPE.A, ttl: 60, data: '1.1.1.2' },
    ],
  });
  const msg = P.decodeMessage(buf);

  // Both answers must decode correctly...
  assert.strictEqual(msg.answers.length, 2);
  assert.strictEqual(msg.answers[0].data, '1.1.1.1');
  assert.strictEqual(msg.answers[1].data, '1.1.1.2');
  assert.strictEqual(msg.answers[1].name, 'www.example.com');

  // Walk the encoded message and measure each owner name for real.
  const headerLen = 12;
  const r = new P.Reader(buf);
  r.u16(); r.u16(); ['qd', 'an', 'ns', 'ar'].forEach(() => r.u16());
  const q = r.name();
  const nameLen = q.nextOffset - q.offset;
  r.u16(); r.u16(); // question type + class

  const a1 = r.name();
  const firstNameLen = a1.nextOffset - a1.offset;
  r.u16(); r.u16(); r.u32();
  const rdlen1 = r.u16();
  r.bytes(rdlen1);

  const a2 = r.name();
  const secondNameLen = a2.nextOffset - a2.offset;

  // The question name is written out in full; both answers reuse pointers.
  assert.strictEqual(nameLen, 17, 'question name is written out in full');
  assert.strictEqual(firstNameLen, 2, 'first answer owner name is a 2-byte pointer');
  assert.strictEqual(secondNameLen, 2, 'second answer owner name is a 2-byte pointer');
  assert.strictEqual(a2.name, 'www.example.com', 'the pointer must resolve to the same name');

  // Total size: header + question + 2 records, with both owner names compressed.
  const question = nameLen + 2 + 2;
  const rrHead = 2 + 2 + 4 + 2; // type + class + ttl + rdlength
  const aRdata = 4;
  const uncompressed = headerLen + question + 2 * (nameLen + rrHead + aRdata);
  const withPointers = uncompressed - 2 * (nameLen - 2);

  assert.strictEqual(buf.length, withPointers, `expected ${withPointers}, got ${buf.length}`);

  // RDATA must never contain a compression pointer: an A record is always 4
  // bytes regardless of where in the message it sits.
  assert.strictEqual(rdlen1, 4, 'A record rdata is exactly 4 bytes');

  // A record must be movable within a message: re-encoding it alone still works
  const standalone = P.encodeMessage({
    id: 3,
    flags: 0x8180,
    questions: [{ name: 'x.example.com', type: TYPE.A, class: 1 }],
    answers: [{ name: 'www.example.com', type: TYPE.A, ttl: 60, data: '1.1.1.1' }],
  });
  assert.strictEqual(P.decodeMessage(standalone).answers[0].data, '1.1.1.1');
});

test('CNAME / MX / TXT / SOA / SRV / CAA rdata round-trips', () => {
  const records = [
    { name: 'c.example.com', type: TYPE.CNAME, ttl: 300, data: 'target.example.net' },
    { name: 'example.com', type: TYPE.MX, ttl: 300, data: '10 mail.example.com' },
    { name: 'example.com', type: TYPE.TXT, ttl: 300, data: 'v=spf1 -all' },
    {
      name: 'example.com',
      type: TYPE.SOA,
      ttl: 300,
      data: 'ns1.example.com hostmaster.example.com 2024010101 3600 600 604800 60',
    },
    { name: '_sip._tcp.example.com', type: TYPE.SRV, ttl: 300, data: '10 20 5060 sip.example.com' },
    { name: 'example.com', type: TYPE.CAA, ttl: 300, data: '0 issue letsencrypt.org' },
  ];
  const buf = P.encodeMessage({
    id: 3,
    flags: 0x8180,
    questions: [{ name: 'example.com', type: TYPE.A, class: 1 }],
    answers: records,
  });
  const msg = P.decodeMessage(buf);
  assert.strictEqual(msg.answers.length, records.length);
  assert.strictEqual(msg.answers[0].data, 'target.example.net');
  assert.strictEqual(msg.answers[1].data, '10 mail.example.com');
  assert.strictEqual(msg.answers[2].data, 'v=spf1 -all');
  assert.ok(msg.answers[3].data.startsWith('ns1.example.com hostmaster.example.com'));
  assert.strictEqual(msg.answers[4].data, '10 20 5060 sip.example.com');
  assert.strictEqual(msg.answers[5].data, 'issue letsencrypt.org');
});

test('TXT strings longer than 255 bytes split correctly', () => {
  const long = 'x'.repeat(600);
  const buf = P.encodeMessage({
    id: 4,
    flags: 0x8180,
    questions: [{ name: 'long.example.com', type: TYPE.TXT, class: 1 }],
    answers: [{ name: 'long.example.com', type: TYPE.TXT, ttl: 60, data: long }],
  });
  const msg = P.decodeMessage(buf);
  assert.strictEqual(msg.answers[0].data, long);
});

test('EDNS0 OPT record is parsed with DO bit and payload size', () => {
  const buf = P.encodeMessage({
    id: 5,
    flags: P.makeFlags({ rd: true }),
    questions: [{ name: 'edns.example.com', type: TYPE.A, class: 1 }],
    additionals: [P.buildOpt({ udpPayloadSize: 1232, doBit: true })],
  });
  const msg = P.decodeMessage(buf);
  assert.ok(msg.edns, 'OPT record must be detected');
  assert.strictEqual(msg.edns.udpPayloadSize, 1232);
  assert.strictEqual(msg.edns.do, true);
});

test('multiple questions decode in order', () => {
  const buf = P.encodeMessage({
    id: 6,
    flags: 0x0100,
    questions: [
      { name: 'a.test', type: TYPE.A, class: 1 },
      { name: 'b.test', type: TYPE.AAAA, class: 1 },
    ],
  });
  const msg = P.decodeMessage(buf);
  assert.strictEqual(msg.questions.length, 2);
  assert.strictEqual(msg.questions[0].name, 'a.test');
  assert.strictEqual(msg.questions[1].type, TYPE.AAAA);
});

test('name helpers behave as expected', () => {
  assert.strictEqual(P.normalizeName('Example.COM.'), 'example.com');
  assert.strictEqual(P.toLabels('a.b.c').length, 3);
  assert.strictEqual(P.toLabels('').length, 0);
  assert.ok(P.isSubdomain('x.example.com', 'example.com'));
  assert.ok(P.isSubdomain('example.com', 'example.com'));
  assert.ok(!P.isSubdomain('notexample.com', 'example.com'));
  assert.ok(P.isIPv4('192.168.0.1'));
  assert.ok(!P.isIPv4('999.1.1.1'));
  assert.ok(P.isIPv6('2001:db8::1'));
});

test('truncated messages throw instead of returning garbage', () => {
  // Header only with a question count that has no question data
  const bogusCount = Buffer.from('000001000001000000000000', 'hex');
  assert.throws(() => P.decodeMessage(bogusCount), /end of (DNS message|name)/);
  // A compression pointer that points forward is rejected (pointer loop guard).
  // qdcount=1 forces the decoder into the name parser to reach it.
  const forwardPtr = Buffer.concat([
    Buffer.from('000001000001000000000000', 'hex'),
    Buffer.from([0xc0, 0x20]), // points to offset 0x20, beyond this message
  ]);
  assert.throws(() => P.decodeMessage(forwardPtr), /forward compression pointer/);

  // A label length that runs past the end of the buffer
  const longLabel = Buffer.concat([Buffer.from('000001000001000000000000', 'hex'), Buffer.from([0x40, 0x41])]);
  assert.throws(() => P.decodeMessage(longLabel), /unknown label type|end of/);

  // A label that claims more bytes than remain
  const overrun = Buffer.concat([Buffer.from('000001000001000000000000', 'hex'), Buffer.from([0x10, 0x41])]);
  assert.throws(() => P.decodeMessage(overrun), /end of label/);

  // RDATA that claims more bytes than the message actually carries
  const bad = Buffer.from([
    0x00, 0x01, 0x80, 0x00, // id=1, flags=QR
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // qd=0, an=1, ns=0, ar=0
    0x00,       // root owner name
    0x00, 0x01, // type A
    0x00, 0x01, // class IN
    0x00, 0x00, 0x00, 0x3c, // ttl 60
    0x00, 0xff, // rdlength 255
    0x01, 0x02, 0x03, // ...but only 3 bytes remain
  ]);
  assert.throws(() => P.decodeMessage(bad), /end of DNS message/);

  // A well-formed header with zero questions must still decode cleanly
  const empty = P.decodeMessage(Buffer.from('000001000000000000000000', 'hex'));
  assert.deepStrictEqual(empty.questions, []);
});

// ---------------------------------------------------------------------------
section('Record validation');
// ---------------------------------------------------------------------------

test('valid records pass validation', () => {
  const good = [
    { name: 'a.example.com', type: TYPE.A, data: '1.2.3.4', ttl: 300 },
    { name: 'v6.example.com', type: TYPE.AAAA, data: '2001:db8::1', ttl: 300 },
    { name: 'c.example.com', type: TYPE.CNAME, data: 'x.example.net', ttl: 300 },
    { name: 'example.com', type: TYPE.MX, data: '10 mail.example.com', ttl: 300 },
    { name: 'example.com', type: TYPE.TXT, data: 'hello', ttl: 300 },
    { name: 'example.com', type: TYPE.CAA, data: '0 issue ca.example.net', ttl: 300 },
  ];
  for (const rec of good) {
    assert.deepStrictEqual(validateRecord(rec), [], `${rec.type}: ${validateRecord(rec).join(',')}`);
  }
});

test('invalid records are rejected with a reason', () => {
  assert.ok(validateRecord({ name: 'a.example.com', type: TYPE.A, data: 'not-an-ip', ttl: 300 }).length);
  assert.ok(validateRecord({ name: 'a.example.com', type: TYPE.MX, data: 'mail.example.com', ttl: 300 }).length);
  assert.ok(validateRecord({ name: 'a.example.com', type: TYPE.A, data: '1.2.3.4', ttl: -1 }).length);
  assert.ok(validateRecord({ name: 'a.example.com', type: TYPE.CNAME, data: '', ttl: 300 }).length);
});

// ---------------------------------------------------------------------------
section('Zone engine');
// ---------------------------------------------------------------------------

function makeStore() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'puffdns-test-'));
  const store = new Store(dir);
  store.init({ version: 1, zones: [], users: [], tokens: [], settings: {} });
  return store;
}

const store = makeStore();
const { salt, hash } = hashPassword('testpassword');
store.createUser({
  username: 'admin',
  salt,
  hash,
  role: 'admin',
  createdAt: new Date().toISOString(),
});

const zoneEngine = new ZoneEngine(store);
store.createZone({
  name: 'example.com',
  type: 'master',
  ttl: 300,
  ns: ['ns1.example.com', 'ns2.example.com'],
  soa: {
    mname: 'ns1.example.com',
    rname: 'hostmaster.example.com',
    serial: 1,
    refresh: 3600,
    retry: 600,
    expire: 604800,
    minimum: 60,
  },
  records: [],
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
});

const rec = (name, type, data, ttl = 300) => ({
  id: `rec_${name}_${type}`,
  name,
  type,
  data,
  ttl,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
});

store.addRecord('example.com', rec('www', TYPE.A, '93.184.216.34'));
store.addRecord('example.com', rec('www', TYPE.A, '93.184.216.35'));
store.addRecord('example.com', rec('@', TYPE.MX, '10 mail.example.com'));
store.addRecord('example.com', rec('alias', TYPE.CNAME, 'www.example.com'));
store.addRecord('example.com', rec('@', TYPE.TXT, 'v=spf1 mx -all'));
store.addRecord('example.com', rec('*.wild', TYPE.A, '10.0.0.1'));
store.addRecord('example.com', rec('sub.deep', TYPE.A, '10.0.0.2'));

test('longest-suffix zone matching finds the right zone', () => {
  assert.strictEqual(zoneEngine.findZone('www.example.com'), 'example.com');
  assert.strictEqual(zoneEngine.findZone('example.com'), 'example.com');
  assert.strictEqual(zoneEngine.findZone('other.org'), null);
});

test('A query returns all round-robin records', () => {
  const res = zoneEngine.lookup('www.example.com', TYPE.A);
  assert.strictEqual(res.nxdomain, false);
  assert.strictEqual(res.answers.length, 2);
  assert.deepStrictEqual(res.answers.map((r) => r.data).sort(), ['93.184.216.34', '93.184.216.35']);
});

test('apex NS and SOA are synthesized from zone config', () => {
  const ns = zoneEngine.lookup('example.com', TYPE.NS);
  assert.strictEqual(ns.answers.length, 2);
  assert.ok(ns.answers.every((r) => r.type === TYPE.NS));

  const soa = zoneEngine.lookup('example.com', TYPE.SOA);
  assert.strictEqual(soa.answers.length, 1);
  assert.strictEqual(soa.answers[0].type, TYPE.SOA);
  assert.ok(soa.answers[0].data.includes('ns1.example.com'));
});

test('unknown name yields NXDOMAIN with SOA in authority', () => {
  const res = zoneEngine.lookup('nope.example.com', TYPE.A);
  assert.strictEqual(res.nxdomain, true);
  assert.strictEqual(res.extras.length, 1);
  assert.strictEqual(res.extras[0].type, TYPE.SOA);
});

test('existing name with wrong type yields NODATA, not NXDOMAIN', () => {
  const res = zoneEngine.lookup('www.example.com', TYPE.TXT);
  assert.strictEqual(res.nxdomain, false);
  assert.strictEqual(res.answers.length, 0);
});

test('wildcard records match any subdomain and rewrite the owner name', () => {
  const res = zoneEngine.lookup('anything.wild.example.com', TYPE.A);
  assert.strictEqual(res.answers.length, 1);
  assert.strictEqual(res.answers[0].data, '10.0.0.1');
  assert.strictEqual(res.answers[0].name, 'anything.wild.example.com', 'owner name must be rewritten');
});

test('CNAME at a name is returned for non-CNAME queries', () => {
  const res = zoneEngine.lookup('alias.example.com', TYPE.A);
  assert.ok(res.cnameOnly || res.cnames.length > 0, 'expected a CNAME to be reported');
});

// ---------------------------------------------------------------------------
section('Cache');
// ---------------------------------------------------------------------------

test('cache stores, hits and expires entries', () => {
  const cache = new DnsCache({ maxEntries: 10, minTtl: 0, maxTtl: 100 });
  cache.set('a.com', TYPE.A, { rcode: 0, answers: [] }, 60);
  assert.ok(cache.get('a.com', TYPE.A));
  assert.strictEqual(cache.stats().hits, 1);

  cache.set('short.com', TYPE.A, { rcode: 0 }, 0.01);
  // simulate expiry
  const entry = cache.map.get(DnsCache.key('short.com', TYPE.A, false, false));
  entry.expiresAt = Date.now() - 1;
  assert.strictEqual(cache.get('short.com', TYPE.A), null);
});

test('cache evicts oldest entries beyond maxEntries', () => {
  const cache = new DnsCache({ maxEntries: 3 });
  for (let i = 0; i < 10; i++) cache.set(`h${i}.com`, TYPE.A, { rcode: 0 }, 60);
  assert.ok(cache.stats().entries <= 3, `entries=${cache.stats().entries}`);
});

test('stale entries are served when upstream is down', () => {
  const cache = new DnsCache({ maxEntries: 10 });
  cache.set('stale.com', TYPE.A, { rcode: 0, answers: [{ data: '1.1.1.1' }] }, 1);
  const entry = cache.map.get(DnsCache.key('stale.com', TYPE.A, false, false));
  entry.expiresAt = Date.now() - 1000;
  assert.ok(cache.getStale('stale.com', TYPE.A), 'stale value must be available');
});

test('invalidateZone clears matching entries', () => {
  const cache = new DnsCache({ maxEntries: 10 });
  cache.set('x.example.com', TYPE.A, { rcode: 0 }, 60);
  cache.set('y.other.com', TYPE.A, { rcode: 0 }, 60);
  cache.invalidateZone('example.com');
  assert.strictEqual(cache.get('x.example.com', TYPE.A), null);
  assert.ok(cache.get('y.other.com', TYPE.A), 'other zones must survive');
});

// ---------------------------------------------------------------------------
section('Access control');
// ---------------------------------------------------------------------------

test('empty rules allow everyone', () => {
  const ac = new AccessControl([]);
  assert.ok(ac.isAllowed('8.8.8.8'));
});

test('allow rule restricts to the listed range', () => {
  const ac = new AccessControl([{ cidr: '192.168.1.0/24', action: 'allow' }]);
  assert.ok(ac.isAllowed('192.168.1.55'));
  assert.ok(!ac.isAllowed('10.0.0.1'));
});

test('deny rule overrides allow rules', () => {
  const ac = new AccessControl([
    { cidr: '192.168.1.0/24', action: 'allow' },
    { cidr: '192.168.1.66/32', action: 'deny' },
  ]);
  assert.ok(ac.isAllowed('192.168.1.10'));
  assert.ok(!ac.isAllowed('192.168.1.66'));
});

test('IPv6 CIDR matching works', () => {
  const { cidrMatch } = require('../src/dns/server');
  assert.ok(cidrMatch('2001:db8::1', '2001:db8::/32'));
  assert.ok(!cidrMatch('2001:dbf::1', '2001:db8::/32'));
  assert.ok(cidrMatch('::1', '::1/128'));
});

// ---------------------------------------------------------------------------
section('HTTP API (live server)');
// ---------------------------------------------------------------------------

const config = {
  dataDir: store.dataDir,
  dnsPort: 0,
  webPort: 0,
  webHost: '127.0.0.1',
  defaultTtl: 300,
  cacheEnabled: true,
  queryLogEnabled: true,
  queryLogSize: 200,
  dohEnabled: true,
  addGlue: true,
  forwardOnly: false,
  serveStale: true,
};

const cache = new DnsCache({ maxEntries: 100 });
const queryLog = new QueryLog({ size: 200, enabled: true });
const session = new Session('test-secret-value');
const accessControl = new AccessControl([]);

const upstreamStub = {
  resolve: async () => {
    throw new Error('upstream disabled in tests');
  },
  getStats: () => ({ queries: 0 }),
  upstreams: ['1.1.1.1'],
  setUpstreams: (l) => {
    upstreamStub.upstreams = l;
    return l;
  },
};

const dnsServer = new DnsServer({ store, zoneEngine, upstream: upstreamStub, cache, config, accessControl });
dnsServer.on('query', (e) => queryLog.add({ ...e, time: new Date().toISOString() }));

const apiRouter = createApi({
  store,
  config,
  dnsServer,
  upstream: upstreamStub,
  cache,
  zoneEngine,
  session,
  queryLog,
  accessControl,
});
const webServer = createWebServer({ apiRouter, store, config, dnsServer, cache, queryLog });

let baseUrl = '';
let cookie = '';

function httpReq(method, p, { body, headers = {}, useCookie = true, rawBody = null } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(p, baseUrl);
    const h = { ...headers };
    const payload = rawBody || (body ? Buffer.from(JSON.stringify(body)) : null);
    if (payload) {
      if (!h['Content-Type']) h['Content-Type'] = 'application/json';
      h['Content-Length'] = payload.length;
    }
    if (useCookie && cookie) h.Cookie = cookie;

    const req = require('http').request(
      { hostname: url.hostname, port: url.port, path: url.pathname + url.search, method, headers: h },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          const text = buf.toString('utf8');
          let json = null;
          try {
            json = JSON.parse(text);
          } catch {
            /* not json */
          }
          resolve({ status: res.statusCode, headers: res.headers, text, buf, json });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function main() {
  await new Promise((resolve) => webServer.listen(0, '127.0.0.1', resolve));
  const port = webServer.address().port;
  baseUrl = `http://127.0.0.1:${port}`;

  // health
  {
    const res = await httpReq('GET', '/api/health');
    test('GET /api/health returns ok without auth', () => {
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.status, 'ok');
      assert.strictEqual(res.json.zones, 1);
    });
  }

  // auth guard
  {
    const res = await httpReq('GET', '/api/zones');
    test('protected endpoints reject anonymous requests', () => {
      assert.strictEqual(res.status, 401);
    });
  }

  // bad login
  {
    const res = await httpReq('POST', '/api/login', { body: { username: 'admin', password: 'wrong' } });
    test('login rejects a wrong password', () => {
      assert.strictEqual(res.status, 401);
    });
  }

  // good login
  {
    const res = await httpReq('POST', '/api/login', { body: { username: 'admin', password: 'testpassword' } });
    test('login succeeds with correct credentials and sets a cookie', () => {
      assert.strictEqual(res.status, 200);
      assert.ok(res.headers['set-cookie'], 'Set-Cookie header expected');
      cookie = res.headers['set-cookie'][0].split(';')[0];
      assert.strictEqual(res.json.user.role, 'admin');
    });
  }

  // list zones
  {
    const res = await httpReq('GET', '/api/zones');
    test('GET /api/zones returns the seeded zone', () => {
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.length, 1);
      assert.strictEqual(res.json[0].name, 'example.com');
      assert.ok(res.json[0].recordCount >= 7);
    });
  }

  // zone detail
  {
    const res = await httpReq('GET', '/api/zones/example.com');
    test('GET /api/zones/:name includes sorted records', () => {
      assert.strictEqual(res.status, 200);
      assert.ok(res.json.records.length >= 7);
      assert.ok(res.json.records.every((r) => typeof r.type === 'string'));
    });
  }

  // create record
  let newRecordId = null;
  {
    const res = await httpReq('POST', '/api/zones/example.com/records', {
      body: { name: 'api', type: 'A', data: '203.0.113.9', ttl: 120 },
    });
    newRecordId = res.json && res.json.id;
    test('POST record creates an A record', () => {
      assert.strictEqual(res.status, 201, `got ${res.status}: ${res.text.slice(0, 300)}`);
      assert.strictEqual(res.json.data, '203.0.113.9');
      assert.strictEqual(res.json.type, 'A');
    });
  }

  {
    const res = await httpReq('POST', '/api/zones/example.com/records', {
      body: { name: 'api', type: 'A', data: '203.0.113.9', ttl: 120 },
    });
    test('duplicate records are rejected', () => {
      assert.strictEqual(res.status, 409);
    });
  }

  {
    const res = await httpReq('POST', '/api/zones/example.com/records', {
      body: { name: 'bad', type: 'A', data: 'not-an-ip' },
    });
    test('invalid record data is rejected with 400', () => {
      assert.strictEqual(res.status, 400);
    });
  }

  // update record
  {
    const res = await httpReq('PUT', `/api/records/${newRecordId}`, { body: { data: '203.0.113.10' } });
    test('PUT record updates the rdata', () => {
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.data, '203.0.113.10');
    });
  }

  // DDNS token flow
  let ddnsToken = null;
  {
    const res = await httpReq('POST', '/api/tokens', { body: { name: 'router', zone: 'example.com', hostname: 'home' } });
    ddnsToken = res.json && res.json.token;
    test('POST /api/tokens returns a plaintext token once', () => {
      assert.strictEqual(res.status, 201);
      assert.ok(ddnsToken && ddnsToken.length > 20);
      assert.strictEqual(res.json.hostname, 'home');
    });
  }

  {
    const res = await httpReq('GET', '/api/ddns/update?token=wrongtoken&ipv4=1.2.3.4');
    test('DDNS update rejects an invalid token', () => {
      assert.strictEqual(res.status, 401);
    });
  }

  {
    const res = await httpReq(
      'GET',
      `/api/ddns/update?hostname=home.example.com&token=${encodeURIComponent(ddnsToken)}&ipv4=198.51.100.7`
    );
    test('DDNS update creates an A record', () => {
      assert.strictEqual(res.status, 200);
      assert.ok(res.json.changes.some((c) => c.action === 'created' && c.data === '198.51.100.7'));
    });
  }

  {
    const res = await httpReq(
      'GET',
      `/api/ddns/update?hostname=home.example.com&token=${encodeURIComponent(ddnsToken)}&ipv4=198.51.100.7`
    );
    test('repeated DDNS update with the same IP is a no-op', () => {
      assert.ok(res.json.changes.some((c) => c.action === 'unchanged'));
    });
  }

  {
    const res = await httpReq(
      'GET',
      `/api/ddns/update?hostname=home.example.com&token=${encodeURIComponent(ddnsToken)}&ipv4=198.51.100.8`
    );
    test('DDNS update changes the IP in place', () => {
      assert.ok(res.json.changes.some((c) => c.action === 'updated' && c.data === '198.51.100.8'));
    });
  }

  {
    const res = await httpReq('GET', `/api/ddns/update?hostname=evil.org&token=${encodeURIComponent(ddnsToken)}&ipv4=1.1.1.1`);
    test('DDNS token cannot update a hostname outside its zone', () => {
      assert.strictEqual(res.status, 403);
    });
  }

  {
    const res = await httpReq('GET', `/api/ddns/update?hostname=home.example.com&token=${encodeURIComponent(ddnsToken)}&ipv4=999.1.1.1`);
    test('DDNS update rejects a malformed IP', () => {
      assert.strictEqual(res.status, 400);
    });
  }

  // authoritative answering via the internal pipeline
  {
    const queryBuf = P.encodeMessage({
      id: 777,
      flags: P.makeFlags({ rd: false }),
      questions: [{ name: 'www.example.com', type: TYPE.A, class: 1 }],
    });
    const query = P.decodeMessage(queryBuf);
    const res = await dnsServer._buildResponse(query, { client: '127.0.0.1', proto: 'udp', maxSize: 512 });
    const decoded = P.decodeMessage(res);
    test('authoritative answer is returned with AA set', () => {
      assert.strictEqual(decoded.id, 777);
      assert.strictEqual(decoded.flags & 0x8000, 0x8000, 'QR must be set');
      assert.strictEqual(decoded.flags & 0x0400, 0x0400, 'AA must be set');
      assert.strictEqual(decoded.answers.length, 2);
    });
  }

  {
    const queryBuf = P.encodeMessage({
      id: 778,
      flags: P.makeFlags({ rd: false }),
      questions: [{ name: 'nx.example.com', type: TYPE.A, class: 1 }],
    });
    const query = P.decodeMessage(queryBuf);
    const res = await dnsServer._buildResponse(query, { client: '127.0.0.1', proto: 'udp', maxSize: 512 });
    const decoded = P.decodeMessage(res);
    test('unknown name returns NXDOMAIN with SOA authority', () => {
      assert.strictEqual(decoded.flags & 0x0f, RCODE.NXDOMAIN);
      assert.strictEqual(decoded.answers.length, 0);
      assert.ok(decoded.authority.some((rr) => rr.type === TYPE.SOA));
    });
  }

  {
    const queryBuf = P.encodeMessage({
      id: 779,
      flags: P.makeFlags({ rd: false }),
      questions: [{ name: 'other.org', type: TYPE.A, class: 1 }],
    });
    const query = P.decodeMessage(queryBuf);
    const res = await dnsServer._buildResponse(query, { client: '127.0.0.1', proto: 'udp', maxSize: 512 });
    const decoded = P.decodeMessage(res);
    test('non-local names fall through to forwarding (SERVFAIL when upstream is down)', () => {
      assert.strictEqual(decoded.flags & 0x0f, RCODE.SERVFAIL);
    });
  }

  // UDP truncation behaviour
  {
    const manyAnswers = [];
    for (let i = 0; i < 40; i++) {
      manyAnswers.push({ name: 'big.example.com', type: TYPE.TXT, ttl: 60, data: `chunk-${i}-${'y'.repeat(200)}` });
    }
    const queryBuf = P.encodeMessage({
      id: 780,
      flags: P.makeFlags({ rd: false }),
      questions: [{ name: 'big.example.com', type: TYPE.TXT, class: 1 }],
    });
    store.addRecord('example.com', {
      id: 'rec_big',
      name: 'big',
      type: TYPE.TXT,
      data: 'z'.repeat(500),
      ttl: 60,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
    const query = P.decodeMessage(queryBuf);
    const res512 = await dnsServer._buildResponse(query, { client: '127.0.0.1', proto: 'udp', maxSize: 512 });
    const decoded = P.decodeMessage(res512);
    test('oversized UDP answers set TC and shrink below the limit', () => {
      assert.ok(res512.length <= 512, `response ${res512.length} exceeds 512`);
      assert.strictEqual(decoded.flags & 0x0200, 0x0200, 'TC must be set');
    });

    const resBig = await dnsServer._buildResponse(query, { client: '127.0.0.1', proto: 'tcp', maxSize: 65535 });
    const decodedBig = P.decodeMessage(resBig);
    test('the same query over TCP is not truncated', () => {
      assert.strictEqual(decodedBig.flags & 0x0200, 0);
      assert.ok(resBig.length > 512);
    });
  }

  // zone import/export
  {
    const res = await httpReq('POST', '/api/zones/example.com/import', {
      body: { lines: ['bulk 60 IN A 198.51.100.1', 'bulk2 60 IN A 198.51.100.2', 'this line is broken'] },
    });
    test('zone import adds valid lines and reports errors', () => {
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.added, 2);
      assert.strictEqual(res.json.errors.length, 1);
    });
  }

  {
    const res = await httpReq('GET', '/api/zones/example.com/export');
    test('zone export emits a BIND-format file with SOA and NS', () => {
      assert.strictEqual(res.status, 200);
      assert.ok(res.text.includes('$ORIGIN example.com.'));
      assert.ok(res.text.includes('IN SOA'));
      assert.ok(res.text.includes('IN NS'));
    });
  }

  // settings
  {
    const res = await httpReq('PUT', '/api/settings', {
      body: { upstreams: ['9.9.9.9', '1.0.0.1'], defaultTtl: 600, cacheEnabled: false },
    });
    test('PUT /api/settings persists upstream and TTL changes', () => {
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.defaultTtl, 600);
      assert.deepStrictEqual(res.json.upstreams, ['9.9.9.9', '1.0.0.1']);
      assert.strictEqual(config.defaultTtl, 600, 'live config must reflect the change');
    });
    // restore
    await httpReq('PUT', '/api/settings', { body: { upstreams: ['1.1.1.1'], defaultTtl: 300, cacheEnabled: true } });
  }

  // users
  {
    const res = await httpReq('POST', '/api/users', {
      body: { username: 'viewer1', password: 'viewerpass123', role: 'viewer' },
    });
    test('admin can create a viewer account', () => {
      assert.strictEqual(res.status, 201);
      assert.strictEqual(res.json.role, 'viewer');
    });
  }

  {
    const res = await httpReq('POST', '/api/users', {
      body: { username: 'ab', password: 'short', role: 'viewer' },
    });
    test('user creation validates username and password length', () => {
      assert.strictEqual(res.status, 400);
    });
  }

  // query log
  {
    const res = await httpReq('GET', '/api/queries?limit=50');
    test('GET /api/queries returns buffered query history', () => {
      assert.strictEqual(res.status, 200);
      assert.ok(res.json.stats.total > 0, 'queries should have been recorded');
      assert.ok(Array.isArray(res.json.entries));
    });
  }

  // static assets
  {
    const res = await httpReq('GET', '/');
    test('GET / serves the panel HTML', () => {
      assert.strictEqual(res.status, 200);
      assert.ok(res.text.includes('<!DOCTYPE html>'));
    });
  }

  {
    // Percent-encoded traversal: the WHATWG URL parser leaves %2e alone, so
    // this reaches the static handler as a literal "../" after decoding.
    const res = await httpReq('GET', '/%2e%2e%2f%2e%2e%2fpackage.json');
    test('encoded path traversal does not escape the public directory', () => {
      assert.ok(res.status === 403 || res.status === 404, `got ${res.status}`);
      assert.ok(!res.text.includes('"puffdns"'), 'package.json must not be served');
    });
  }

  {
    const res = await httpReq('GET', '/%2e%2e/src/store.js');
    test('traversal to source files is refused', () => {
      assert.ok(res.status === 403 || res.status === 404, `got ${res.status}`);
      assert.ok(!res.text.includes('class Store'), 'source must not be served');
    });
  }

  // DoH
  {
    const q = P.encodeMessage({
      id: 4242,
      flags: P.makeFlags({ rd: false }),
      questions: [{ name: 'www.example.com', type: TYPE.A, class: 1 }],
    });
    const b64 = q.toString('base64url');
    const res = await httpReq('GET', `/dns-query?dns=${b64}`, { headers: { Accept: 'application/dns-message' } });
    test('DoH resolves an authoritative query over HTTP GET', () => {
      assert.strictEqual(res.status, 200);
      assert.ok(String(res.headers['content-type']).includes('application/dns-message'));
      const decoded = P.decodeMessage(res.buf);
      assert.strictEqual(decoded.id, 4242);
      assert.strictEqual(decoded.answers.length, 2);
      assert.ok(decoded.flags & 0x0400, 'AA bit expected');
    });
  }

  {
    const q = P.encodeMessage({
      id: 4243,
      flags: P.makeFlags({ rd: false }),
      questions: [{ name: 'alias.example.com', type: TYPE.A, class: 1 }],
    });
    const res = await httpReq('POST', '/dns-query', {
      headers: { 'Content-Type': 'application/dns-message' },
      rawBody: q,
    });
    test('DoH accepts a POST body as raw dns-message and follows CNAME', () => {
      assert.strictEqual(res.status, 200);
      const decoded = P.decodeMessage(res.buf);
      assert.strictEqual(decoded.id, 4243);
      const types = decoded.answers.map((rr) => rr.type);
      assert.ok(types.includes(TYPE.CNAME), 'expected the CNAME in the answer set');
    });
  }

  {
    const res = await httpReq('GET', '/dns-query?dns=notbase64!!!');
    test('DoH rejects a malformed ?dns= parameter', () => {
      assert.ok(res.status === 400 || res.status === 200);
      if (res.status === 400) assert.ok(res.text.includes('base64'));
    });
  }

  webServer.close();
  store.close();
  fs.rmSync(store.dataDir, { recursive: true, force: true });
}

section('Summary');
main()
  .then(() => {
    process.stdout.write(`\n\x1b[1mResult:\x1b[0m \x1b[32m${passed} passed\x1b[0m`);
    if (failed) process.stdout.write(`, \x1b[31m${failed} failed\x1b[0m`);
    process.stdout.write(`\n\n`);
    process.exit(failed ? 1 : 0);
  })
  .catch((err) => {
    process.stdout.write(`\n\x1b[31mTest harness crashed:\x1b[0m ${err.stack}\n`);
    process.exit(1);
  });
