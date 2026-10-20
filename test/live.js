'use strict';

/**
 * Live integration check: starts the real server on high ports, then queries
 * it over real UDP and TCP sockets the way a resolver would.
 *
 *   node test/live.js
 */

const { spawn } = require('child_process');
const dgram = require('dgram');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');

const P = require('../src/dns/packet');
const { TYPE } = require('../src/dns/types');

const ROOT = path.join(__dirname, '..');
const DNS_PORT = 15353; // unprivileged, so no root needed
const WEB_PORT = 18080;

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'puffdns-live-'));

let passed = 0;
let failed = 0;

function check(name, cond, detail) {
  if (cond) {
    passed++;
    console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  } else {
    failed++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? `\n      ${detail}` : ''}`);
  }
}

function queryUdp(port, msgBuf, timeout = 8000) {
  const ms = typeof timeout === 'number' && Number.isFinite(timeout) ? timeout : 8000;
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    let settled = false;
    const done = (fn, v) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { sock.close(); } catch { /* ignore */ }
      fn(v);
    };
    const timer = setTimeout(() => done(reject, new Error(`timeout after ${ms}ms`)), ms);

    sock.on('message', (data) => done(resolve, data));
    sock.on('error', (err) => done(reject, err));

    // Bind explicitly to an ephemeral port. Relying on the implicit bind
    // that send() performs leaves Windows reusing a source port across the
    // many short-lived sockets this test creates, and a reply addressed to
    // a port it no longer owns is silently dropped.
    sock.bind(0, '127.0.0.1', () => {
      sock.send(msgBuf, 0, msgBuf.length, port, '127.0.0.1', (err) => {
        if (err) done(reject, err);
      });
    });
  });
}

function queryTcp(port, msgBuf, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: '127.0.0.1', port });
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error('timeout'));
    }, timeout);
    sock.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    sock.on('connect', () => sock.write(P.encodeTcpMessage(msgBuf)));
    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const payload = P.decodeTcpMessage(buf);
      if (payload) {
        clearTimeout(timer);
        sock.end();
        resolve(payload);
      }
    });
  });
}

const q = (name, type, flags = { rd: false }) =>
  P.encodeMessage({ id: 0x4242, flags: P.makeFlags(flags), questions: [{ name, type, class: 1 }] });

function http(method, p, body, cookie) {
  return new Promise((resolve, reject) => {
    const payload = body ? Buffer.from(JSON.stringify(body)) : null;
    const headers = {};
    if (payload) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = payload.length;
    }
    if (cookie) headers.Cookie = cookie;
    const req = require('http').request(
      { host: '127.0.0.1', port: WEB_PORT, path: p, method, headers },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try { json = JSON.parse(text); } catch { /* ignore */ }
          resolve({ status: res.statusCode, headers: res.headers, text, json });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function waitForServer(timeoutMs = 20000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const r = await http('GET', '/api/health');
      if (r.status === 200) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}

(async () => {
  console.log('\n\x1b[1mLive integration test\x1b[0m');
  console.log(`data dir: ${dataDir}`);

  const child = spawn(process.execPath, [path.join(ROOT, 'src', 'index.js')], {
    env: {
      ...process.env,
      PUFFDNS_DATA: dataDir,
      DNS_PORT: String(DNS_PORT),
      WEB_PORT: String(WEB_PORT),
      WEB_HOST: '127.0.0.1',
      ADMIN_PASSWORD: 'livetest123',
      LOG_LEVEL: 'warn',
      // A port nothing listens on, so the forwarding path is deterministic
      // and never depends on the machine running this test having internet.
      UPSTREAMS: 'udp://127.0.0.1:15399',
      UPSTREAM_TIMEOUT: '300',
      FORWARD_ONLY: 'false',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const serverLog = [];
  child.stdout.on('data', (d) => serverLog.push(d.toString()));
  child.stderr.on('data', (d) => serverLog.push(d.toString()));

  // Track every child so an unexpected exit or crash still reaps them. An
  // orphan holding port 15353 would make the next run silently talk to a
  // stale server configured with different upstreams.
  const children = new Set([child]);
  let dataDirRemoved = false;
  const cleanup = () => {
    for (const c of children) {
      try { c.kill('SIGKILL'); } catch { /* already gone */ }
    }
    if (!dataDirRemoved) {
      dataDirRemoved = true;
      try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  };
  for (const sig of ['exit', 'SIGINT', 'SIGTERM', 'uncaughtException']) {
    process.on(sig, () => {
      cleanup();
      if (sig !== 'exit') process.exit(1);
    });
  }
  process.on('beforeExit', cleanup);

  const up = await waitForServer();
  if (!up) {
    console.log('\x1b[31mserver did not start\x1b[0m');
    console.log(serverLog.join(''));
    cleanup();
    process.exit(1);
  }

  // Confirm the DNS port really is ours. If a leftover process from an earlier
  // run still holds it, every later assertion would be testing that stale
  // server instead — with different settings and different upstreams.
  {
    const probe = P.decodeMessage(await queryUdp(DNS_PORT, q('probe.invalid', TYPE.A, { rd: false })));
    const refused = probe.flags & 0x000f;
    check(
      'the DNS port belongs to this run, not a leftover process',
      refused === 2 || refused === 3 || refused === 5,
      `unexpected rcode ${refused}; if a stale server is holding port ${DNS_PORT}, kill it first`
    );
  }

  // ── setup via the API ──────────────────────────────────────
  console.log('\n\x1b[1mSetup via the panel API\x1b[0m');

  const login = await http('POST', '/api/login', { username: 'admin', password: 'livetest123' });
  check('login with the bootstrap password', login.status === 200, `got ${login.status}: ${login.text.slice(0, 200)}`);
  const cookie = login.headers['set-cookie'] ? login.headers['set-cookie'][0].split(';')[0] : '';
  check('session cookie issued', !!cookie);

  const zone = await http('POST', '/api/zones', {
    name: 'test.local',
    ns: ['ns1.test.local'],
  }, cookie);
  check('zone created', zone.status === 201, `got ${zone.status}: ${zone.text.slice(0, 200)}`);

  const records = [
    { name: '@', type: 'A', data: '10.1.2.3' },
    { name: 'www', type: 'A', data: '10.1.2.3' },
    { name: 'www', type: 'A', data: '10.1.2.4' },
    { name: 'v6', type: 'AAAA', data: 'fd00::1' },
    { name: 'alias', type: 'CNAME', data: 'www.test.local' },
    { name: '@', type: 'TXT', data: 'v=spf1 -all' },
    { name: '@', type: 'MX', data: '10 mail.test.local' },
    { name: 'mail', type: 'A', data: '10.1.2.5' },
    { name: '_sip._tcp', type: 'SRV', data: '0 5 5060 sip.test.local' },
    { name: '@', type: 'CAA', data: '0 issue letsencrypt.org' },
    { name: '*.any', type: 'A', data: '10.9.9.9' },
  ];
  let allCreated = true;
  for (const r of records) {
    const res = await http('POST', '/api/zones/test.local/records', r, cookie);
    if (res.status !== 201) {
      allCreated = false;
      console.log(`      ${r.name} ${r.type} -> ${res.status} ${res.text.slice(0, 160)}`);
    }
  }
  check(`all ${records.length} records created`, allCreated);

  // ── UDP queries ────────────────────────────────────────────
  console.log('\n\x1b[1mReal UDP queries on port ' + DNS_PORT + '\x1b[0m');

  {
    const res = P.decodeMessage(await queryUdp(DNS_PORT, q('@.test.local', TYPE.A)));
    check('apex A returns the record', res.answers.some((a) => a.data === '10.1.2.3'), JSON.stringify(res.answers));
    check('apex A is flagged authoritative', (res.flags & 0x0400) !== 0);
  }

  {
    const res = P.decodeMessage(await queryUdp(DNS_PORT, q('www.test.local', TYPE.A)));
    const ips = res.answers.filter((a) => a.type === TYPE.A).map((a) => a.data).sort();
    check('round-robin A returns both addresses', ips.length === 2 && ips[0] === '10.1.2.3' && ips[1] === '10.1.2.4', ips.join(','));
  }

  {
    const res = P.decodeMessage(await queryUdp(DNS_PORT, q('v6.test.local', TYPE.AAAA)));
    check('AAAA round-trips over the wire', res.answers.length === 1 && res.answers[0].data === 'fd00::1', JSON.stringify(res.answers));
  }

  {
    const res = P.decodeMessage(await queryUdp(DNS_PORT, q('alias.test.local', TYPE.A)));
    check('CNAME is followed to its target', res.answers.some((a) => a.type === TYPE.CNAME) && res.answers.some((a) => a.data === '10.1.2.3'), JSON.stringify(res.answers.map((a) => [a.type, a.data])));
  }

  {
    const res = P.decodeMessage(await queryUdp(DNS_PORT, q('test.local', TYPE.TXT)));
    check('TXT preserves internal spaces', res.answers.some((a) => a.data === 'v=spf1 -all'), JSON.stringify(res.answers.map((a) => a.data)));
  }

  {
    const res = P.decodeMessage(await queryUdp(DNS_PORT, q('test.local', TYPE.MX)));
    check('MX parses preference and exchange', res.answers.some((a) => a.type === TYPE.MX && a.data === '10 mail.test.local'), JSON.stringify(res.answers.map((a) => a.data)));
  }

  {
    const res = P.decodeMessage(await queryUdp(DNS_PORT, q('_sip._tcp.test.local', TYPE.SRV)));
    check('SRV round-trips all four fields', res.answers.some((a) => a.type === TYPE.SRV && a.data === '0 5 5060 sip.test.local'), JSON.stringify(res.answers.map((a) => a.data)));
  }

  {
    const res = P.decodeMessage(await queryUdp(DNS_PORT, q('test.local', TYPE.CAA)));
    check('CAA round-trips', res.answers.some((a) => a.type === TYPE.CAA && a.data.includes('letsencrypt.org')), JSON.stringify(res.answers.map((a) => a.data)));
  }

  {
    const res = P.decodeMessage(await queryUdp(DNS_PORT, q('test.local', TYPE.SOA)));
    check('SOA is synthesized at the apex', res.answers.some((a) => a.type === TYPE.SOA && a.data.includes('ns1.test.local')), JSON.stringify(res.answers.map((a) => a.data)));
  }

  {
    const res = P.decodeMessage(await queryUdp(DNS_PORT, q('test.local', TYPE.NS)));
    check('NS is synthesized at the apex', res.answers.some((a) => a.type === TYPE.NS && a.data === 'ns1.test.local'), JSON.stringify(res.answers.map((a) => a.data)));
  }

  {
    const res = P.decodeMessage(await queryUdp(DNS_PORT, q('deep.sub.test.local', TYPE.A)));
    check('unknown name returns NXDOMAIN + SOA', (res.flags & 0x000f) === 3 && res.authority.some((a) => a.type === TYPE.SOA), `rcode=${res.flags & 0xf}`);
  }

  {
    const res = P.decodeMessage(await queryUdp(DNS_PORT, q('www.test.local', TYPE.TXT)));
    check('NODATA for an existing name with the wrong type', (res.flags & 0x000f) === 0 && res.answers.length === 0);
  }

  {
    const res = P.decodeMessage(await queryUdp(DNS_PORT, q('foo.bar.any.test.local', TYPE.A)));
    check('wildcard matches at any depth', res.answers.some((a) => a.data === '10.9.9.9' && a.name === 'foo.bar.any.test.local'), JSON.stringify(res.answers.map((a) => [a.name, a.data])));
  }

  // ── TCP ────────────────────────────────────────────────────
  console.log('\n\x1b[1mReal TCP queries\x1b[0m');

  {
    const res = P.decodeMessage(await queryTcp(DNS_PORT, q('www.test.local', TYPE.A)));
    check('TCP returns the same answers as UDP', res.answers.filter((a) => a.type === TYPE.A).length === 2, JSON.stringify(res.answers.map((a) => a.data)));
  }

  // ── EDNS0 ──────────────────────────────────────────────────
  console.log('\n\x1b[1mEDNS0\x1b[0m');

  {
    const withEdns = P.encodeMessage({
      id: 0x4242,
      flags: P.makeFlags({ rd: false }),
      questions: [{ name: 'www.test.local', type: TYPE.A, class: 1 }],
      additionals: [P.buildOpt({ udpPayloadSize: 4096, doBit: false })],
    });
    const res = P.decodeMessage(await queryUdp(DNS_PORT, withEdns));
    check('query with EDNS0 is answered', res.answers.length === 2);
    check('response echoes an OPT record', !!res.edns && res.edns.udpPayloadSize === 4096, JSON.stringify(res.edns));
  }

  // ── unknown domain falls through to forwarding ─────────────
  {
    const res = P.decodeMessage(await queryUdp(DNS_PORT, q('example.org', TYPE.A), { rd: true }));
    check('non-local domain is forwarded (SERVFAIL when upstream is dead)', (res.flags & 0x000f) === 2, `rcode=${res.flags & 0xf}`);
    check('forwarded response still sets RA', (res.flags & 0x0080) !== 0);
  }

  // ── DoH ────────────────────────────────────────────────────
  console.log('\n\x1b[1mDNS-over-HTTPS\x1b[0m');

  {
    const dnsParam = q('www.test.local', TYPE.A, { rd: true }).toString('base64url');
    const res = await new Promise((resolve, reject) => {
      const req = require('http').request(
        { host: '127.0.0.1', port: WEB_PORT, path: `/dns-query?dns=${dnsParam}`, method: 'GET' },
        (r) => {
          const chunks = [];
          r.on('data', (c) => chunks.push(c));
          r.on('end', () => resolve({ status: r.statusCode, headers: r.headers, buf: Buffer.concat(chunks) }));
        }
      );
      req.on('error', reject);
      req.end();
    });
    const decoded = P.decodeMessage(res.buf);
    check('DoH GET resolves a local record', res.status === 200 && decoded.answers.length === 2, `status=${res.status}`);
    check('DoH returns application/dns-message', String(res.headers['content-type']).includes('application/dns-message'));
  }

  // ── DDNS end-to-end ────────────────────────────────────────
  console.log('\n\x1b[1mDDNS over the public endpoint\x1b[0m');

  let token = null;
  {
    const res = await http('POST', '/api/tokens', { name: 'live', zone: 'test.local', hostname: 'dyn' }, cookie);
    token = res.json && res.json.token;
    check('DDNS token created', res.status === 201 && !!token, `got ${res.status}`);
  }

  {
    const res = await http('GET', `/api/ddns/update?hostname=dyn.test.local&token=${encodeURIComponent(token)}&ipv4=203.0.113.55`);
    check('DDNS update accepted', res.status === 200 && res.json.changes.some((c) => c.action === 'created'), res.text.slice(0, 200));
  }

  {
    const res = P.decodeMessage(await queryUdp(DNS_PORT, q('dyn.test.local', TYPE.A)));
    check('the new A record is immediately resolvable over DNS', res.answers.some((a) => a.data === '203.0.113.55'), JSON.stringify(res.answers.map((a) => a.data)));
  }

  {
    const res = await http('GET', `/api/ddns/update?hostname=dyn.test.local&token=${encodeURIComponent(token)}&ipv4=203.0.113.66&ipv6=fd00::99`);
    check('DDNS update changes v4 and adds v6', res.json.changes.some((c) => c.data === '203.0.113.66' && c.action === 'updated') && res.json.changes.some((c) => c.type === 'AAAA' && c.action === 'created'), res.text.slice(0, 250));
  }

  {
    const v4 = P.decodeMessage(await queryUdp(DNS_PORT, q('dyn.test.local', TYPE.A)));
    const v6 = P.decodeMessage(await queryUdp(DNS_PORT, q('dyn.test.local', TYPE.AAAA)));
    check('both A and AAAA reflect the update', v4.answers.some((a) => a.data === '203.0.113.66') && v6.answers.some((a) => a.data === 'fd00::99'));
  }

  {
    const res = await http('GET', `/api/ddns/update?hostname=dyn.test.local&token=${encodeURIComponent(token)}&clear=true`);
    check('DDNS clear removes both records', res.status === 200, res.text.slice(0, 200));
  }

  {
    const res = P.decodeMessage(await queryUdp(DNS_PORT, q('dyn.test.local', TYPE.A)));
    check('cleared host now returns NXDOMAIN', (res.flags & 0x000f) === 3, `rcode=${res.flags & 0xf}`);
  }

  // ── persistence ────────────────────────────────────────────
  console.log('\n\x1b[1mPersistence across restart\x1b[0m');

  // The on-disk store must already be complete before shutdown: markDirty
  // coalesces writes on a 250ms timer, so read the file directly rather than
  // depending on signal delivery (which differs on Windows).
  const storeFile = path.join(dataDir, 'puffdns.json');
  await new Promise((r) => setTimeout(r, 500));
  const onDisk = JSON.parse(fs.readFileSync(storeFile, 'utf8'));
  check('zones are written to disk without a restart', onDisk.zones.some((z) => z.name === 'test.local'), `zones=${onDisk.zones.length}`);
  check(
    'records are written to disk without a restart',
    onDisk.zones.find((z) => z.name === 'test.local').records.length === records.length,
    `records=${onDisk.zones.find((z) => z.name === 'test.local') ? onDisk.zones.find((z) => z.name === 'test.local').records.length : 'n/a'}`
  );

  // Stop and start a fresh process against the same data directory.
  child.kill('SIGTERM');
  await new Promise((r) => setTimeout(r, 1500));
  if (child.exitCode === null) child.kill('SIGKILL');
  await new Promise((r) => setTimeout(r, 400));

  const child2 = spawn(process.execPath, [path.join(ROOT, 'src', 'index.js')], {
    env: {
      ...process.env,
      PUFFDNS_DATA: dataDir,
      DNS_PORT: String(DNS_PORT),
      WEB_PORT: String(WEB_PORT),
      WEB_HOST: '127.0.0.1',
      ADMIN_PASSWORD: 'livetest123',
      LOG_LEVEL: 'warn',
      UPSTREAMS: 'udp://127.0.0.1:15399',
      UPSTREAM_TIMEOUT: '300',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child2.stdout.on('data', (d) => serverLog.push(d.toString()));
  child2.stderr.on('data', (d) => serverLog.push(d.toString()));
  children.add(child2);

  if (await waitForServer()) {
    const res = P.decodeMessage(await queryUdp(DNS_PORT, q('www.test.local', TYPE.A)));
    check('records still resolve after a restart', res.answers.length === 2, JSON.stringify(res.answers.map((a) => a.data)));

    const relogin = await http('POST', '/api/login', { username: 'admin', password: 'livetest123' });
    check('users survive a restart', relogin.status === 200);

    const cookie2 = relogin.headers['set-cookie'][0].split(';')[0];
    const zones = await http('GET', '/api/zones', null, cookie2);
    check('zones survive a restart', zones.status === 200 && zones.json.some((z) => z.name === 'test.local'));

    const tokenList = await http('GET', '/api/tokens', null, cookie2);
    check('DDNS tokens survive a restart', tokenList.status === 200 && tokenList.json.length >= 1);
  } else {
    check('server restarts', false, serverLog.join('').slice(-600));
  }

  console.log(`\n\x1b[1mResult:\x1b[0m \x1b[32m${passed} passed\x1b[0m${failed ? `, \x1b[31m${failed} failed\x1b[0m` : ''}\n`);
  process.exit(failed ? 1 : 0);
})().catch((err) => {
  console.error('\x1b[31mharness crashed:\x1b[0m', err.stack);
  process.exit(1);
});
