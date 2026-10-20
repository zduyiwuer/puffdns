'use strict';

/**
 * Runs the same assertions the CI docker job makes against the built image,
 * but against a locally spawned server. Lets the smoke-test logic be verified
 * on a machine without Docker.
 *
 *   node test/ci-smoke-local.js
 */

const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');

const ROOT = path.join(__dirname, '..');
const WEB_PORT = 18099;
const DNS_PORT = 15399;
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'puffdns-ci-'));

function get(p, { timeout = 5000 } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port: WEB_PORT, path: p, method: 'GET', timeout },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      }
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.end();
  });
}

(async () => {
  const child = spawn(process.execPath, [path.join(ROOT, 'src', 'index.js')], {
    env: {
      ...process.env,
      PUFFDNS_DATA: dataDir,
      DNS_PORT: String(DNS_PORT),
      WEB_PORT: String(WEB_PORT),
      WEB_HOST: '127.0.0.1',
      ADMIN_PASSWORD: 'ci-smoke-test',
      LOG_LEVEL: 'warn',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const logs = [];
  child.stdout.on('data', (d) => logs.push(d.toString()));
  child.stderr.on('data', (d) => logs.push(d.toString()));

  const done = (code) => {
    try { child.kill('SIGKILL'); } catch { /* ignore */ }
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* ignore */ }
    process.exit(code);
  };

  // 1. Readiness loop, same as CI
  let ready = false;
  for (let i = 0; i < 45; i++) {
    try {
      await get('/api/health', { timeout: 2000 });
      ready = true;
      break;
    } catch {
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  if (!ready) {
    console.error('server never became ready; logs:\n' + logs.join(''));
    done(1);
  }
  console.log('  server became ready');

  // 2. Parse the health JSON the way CI does. This is the assertion that was
  //    silently broken: a literal '"status":"ok"' grep cannot match a
  //    pretty-printed body.
  const health = await get('/api/health');
  const body = JSON.parse(health.body);
  assert.strictEqual(body.status, 'ok', `unexpected status: ${body.status}`);
  console.log('  health JSON parsed, status =', body.status, '| uptime =', body.uptime);
  assert.ok(!health.body.includes('"status":"ok"'), 'sanity: the naive grep form should NOT match');
  console.log('  confirmed the naive grep form does not match (this was the CI bug)');

  // 3. Panel HTML
  const html = await get('/');
  assert.ok(/<title>puffdns/i.test(html.body), 'panel title missing');
  console.log('  panel HTML served');

  // 4. Auth guard
  const zones = await get('/api/zones');
  assert.strictEqual(zones.status, 401, `expected 401, got ${zones.status}`);
  console.log('  auth guard returns 401 for anonymous callers');

  // 5. Login works and the session cookie is accepted
  const login = await new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify({ username: 'admin', password: 'ci-smoke-test' }));
    const req = http.request(
      {
        host: '127.0.0.1',
        port: WEB_PORT,
        path: '/api/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': payload.length },
      },
      (res) => {
        res.resume();
        resolve({ status: res.statusCode, cookie: res.headers['set-cookie'] });
      }
    );
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
  assert.strictEqual(login.status, 200, `login failed: ${login.status}`);
  assert.ok(login.cookie, 'no session cookie');
  console.log('  admin login with ADMIN_PASSWORD works');

  console.log('\nAll CI smoke assertions passed locally.');
  done(0);
})().catch((err) => {
  console.error('smoke check failed:', err.message);
  process.exit(1);
});
