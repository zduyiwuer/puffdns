#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const log = require('./util/log');
const { Store, hashPassword, newId } = require('./store');
const { DnsCache } = require('./dns/cache');
const { ZoneEngine } = require('./dns/zone');
const { UpstreamResolver } = require('./dns/upstream');
const { DnsServer, AccessControl } = require('./dns/server');
const { Session } = require('./web/http');
const { QueryLog } = require('./web/querylog');
const { createApi } = require('./web/api');
const { createWebServer } = require('./web/server');
const { TYPE } = require('./dns/types');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
function envInt(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

function envBool(name, fallback = true) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  return /^(1|true|yes|on)$/i.test(raw);
}

function loadConfig() {
  const dataDir = process.env.PUFFDNS_DATA || process.env.DATA_DIR || path.join(process.cwd(), 'data');
  const dnsPort = envInt('DNS_PORT', 53);
  const webPort = envInt('WEB_PORT', envInt('HTTP_PORT', 8080));
  const webHost = process.env.WEB_HOST || '0.0.0.0';

  return {
    dataDir,
    dnsPort,
    webPort,
    webHost,
    dnsHost: process.env.DNS_HOST || '0.0.0.0',
    logLevel: process.env.LOG_LEVEL || 'info',
    logFile: process.env.LOG_FILE || '',
    defaultTtl: envInt('DEFAULT_TTL', 300),
    cacheEnabled: envBool('CACHE_ENABLED', true),
    cacheMaxEntries: envInt('CACHE_MAX_ENTRIES', 20000),
    cacheMinTtl: envInt('CACHE_MIN_TTL', 0),
    cacheMaxTtl: envInt('CACHE_MAX_TTL', 86400),
    serveStale: envBool('SERVE_STALE', true),
    queryLogEnabled: envBool('QUERY_LOG', true),
    queryLogSize: envInt('QUERY_LOG_SIZE', 1000),
    dohEnabled: envBool('DOH_ENABLED', true),
    addGlue: envBool('ADD_GLUE', true),
    forwardOnly: envBool('FORWARD_ONLY', false),
    upstreams: (process.env.UPSTREAMS || '1.1.1.1,8.8.8.8,9.9.9.9')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    upstreamTimeout: envInt('UPSTREAM_TIMEOUT', 3000),
    bootstrapAdminUser: process.env.ADMIN_USER || 'admin',
    bootstrapAdminPassword: process.env.ADMIN_PASSWORD || '',
    sessionSecretFile: 'session.secret',
  };
}

const DEFAULTS = {
  version: 1,
  zones: [],
  users: [],
  tokens: [],
  settings: {
    upstreams: ['1.1.1.1', '8.8.8.8', '9.9.9.9'],
    cacheEnabled: true,
    cacheMaxEntries: 20000,
    defaultTtl: 300,
    queryLogEnabled: true,
    queryLogSize: 1000,
    accessRules: [],
  },
};

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------
async function main() {
  const config = loadConfig();
  log.setLevel(config.logLevel);
  if (config.logFile) {
    try {
      fs.mkdirSync(path.dirname(config.logFile), { recursive: true });
      log.setFile(config.logFile);
    } catch {
      log.warn(`cannot write log file ${config.logFile}`);
    }
  }

  log.info('puffdns starting');
  log.info(`data directory: ${config.dataDir}`);
  log.info(`node ${process.version} on ${os.platform()}/${os.arch()}`);

  // ---- store ----
  const store = new Store(config.dataDir);
  store.init(DEFAULTS);

  // Settings saved in the panel win over env defaults — but only when the
  // operator did not pin that value in .env. An explicit env var is the more
  // deliberate signal and must not be shadowed by a value stored months ago.
  const settings = store.getSettings();
  const pinned = (name) => process.env[name] !== undefined && process.env[name] !== '';
  if (!pinned('CACHE_ENABLED') && settings.cacheEnabled !== undefined) config.cacheEnabled = settings.cacheEnabled;
  if (!pinned('DEFAULT_TTL') && settings.defaultTtl !== undefined) config.defaultTtl = settings.defaultTtl;
  if (!pinned('QUERY_LOG') && settings.queryLogEnabled !== undefined) config.queryLogEnabled = settings.queryLogEnabled;
  if (!pinned('QUERY_LOG_SIZE') && settings.queryLogSize !== undefined) config.queryLogSize = settings.queryLogSize;

  // ---- session secret ----
  const secretFile = path.join(config.dataDir, config.sessionSecretFile);
  let secret;
  if (fs.existsSync(secretFile)) {
    secret = fs.readFileSync(secretFile, 'utf8').trim();
  } else {
    secret = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(secretFile, secret, { mode: 0o600 });
    log.info('generated a new session secret');
  }
  const session = new Session(secret);

  // ---- bootstrap the first admin account ----
  if (store.listUsers().length === 0) {
    const password = config.bootstrapAdminPassword || crypto.randomBytes(9).toString('base64url');
    const { salt, hash } = hashPassword(password);
    store.createUser({
      username: config.bootstrapAdminUser,
      salt,
      hash,
      role: 'admin',
      email: '',
      createdAt: new Date().toISOString(),
    });
    log.info('='.repeat(64));
    log.info('created the initial admin account');
    log.info(`  username: ${config.bootstrapAdminUser}`);
    if (config.bootstrapAdminPassword) {
      log.info('  password: (from ADMIN_PASSWORD)');
    } else {
      log.info(`  password: ${password}`);
      log.info('  >> save this now, it is not shown again <<');
    }
    log.info('='.repeat(64));
  }

  // ---- DNS engine ----
  const cache = new DnsCache({
    maxEntries: config.cacheMaxEntries,
    minTtl: config.cacheMinTtl,
    maxTtl: config.cacheMaxTtl,
  });
  cache.startGc();

  const zoneEngine = new ZoneEngine(store);
  // Precedence: an explicit UPSTREAMS env var wins over the value saved in the
  // panel. Otherwise editing .env would silently do nothing once the settings
  // file exists, which is a very confusing way to lose a change.
  const upstreamList =
    process.env.UPSTREAMS && process.env.UPSTREAMS.trim()
      ? config.upstreams
      : settings.upstreams && settings.upstreams.length
        ? settings.upstreams
        : config.upstreams;
  const upstream = new UpstreamResolver({
    upstreams: upstreamList,
    timeout: config.upstreamTimeout,
  });

  const accessControl = new AccessControl(settings.accessRules || []);

  const queryLog = new QueryLog({ size: config.queryLogSize, enabled: config.queryLogEnabled });

  const dnsServer = new DnsServer({
    store,
    zoneEngine,
    upstream,
    cache,
    config,
    accessControl,
  });

  dnsServer.on('query', (entry) => {
    queryLog.add({
      time: new Date().toISOString(),
      client: entry.client,
      proto: entry.proto,
      name: entry.name,
      type: entry.type,
      rcode: entry.rcode,
      ms: entry.ms,
      source: entry.source,
      count: entry.count,
    });
  });

  // ---- web ----
  const apiRouter = createApi({
    store,
    config,
    dnsServer,
    upstream,
    cache,
    zoneEngine,
    session,
    queryLog,
    accessControl,
  });

  const webServer = createWebServer({ apiRouter, store, config, dnsServer, cache, queryLog });

  // ---- start listeners ----
  let dnsOk = true;
  try {
    await dnsServer.listen();
  } catch (err) {
    dnsOk = false;
    log.error('DNS listener failed to start:', err.message);
    if (!envBool('WEB_ONLY', false)) {
      log.error('set WEB_ONLY=true to run the panel without the DNS listener');
    }
  }

  await new Promise((resolve, reject) => {
    webServer.once('error', reject);
    webServer.listen(config.webPort, config.webHost, () => {
      webServer.removeListener('error', reject);
      resolve();
    });
  });
  log.info(`web panel listening on http://${config.webHost}:${config.webPort}`);
  log.info(`DNS-over-HTTPS endpoint: http://${config.webHost}:${config.webPort}/dns-query`);
  log.info(`loaded ${store.listZones().length} zone(s), ${store.allRecords().length} record(s)`);

  // ---- graceful shutdown ----
  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    log.info(`received ${signal}, shutting down`);
    try {
      // Flush the store first: if a listener refuses to close we still keep
      // every zone, record and token the user just created.
      store.close();
      cache.stopGc();
      upstream.close();
    } catch (err) {
      log.error('error while closing DNS resources:', err.message);
    }
    try {
      await dnsServer.close();
    } catch (err) {
      log.error('error closing the DNS listener:', err.message);
    }
    await new Promise((resolve) => webServer.close(resolve));
    log.info('bye');
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGHUP', () => shutdown('SIGHUP'));
  process.on('exit', () => {
    // Last-resort safety net: `process.exit()` from anywhere still persists.
    try { store.close(); } catch { /* ignore */ }
  });
  process.on('uncaughtException', (err) => {
    log.error('uncaught exception:', err.stack || err.message);
  });
  process.on('unhandledRejection', (err) => {
    log.error('unhandled rejection:', err && err.stack ? err.stack : String(err));
  });

  return { store, dnsServer, webServer, cache, upstream, queryLog, config };
}

if (require.main === module) {
  main().catch((err) => {
    log.error('fatal:', err.stack || err.message);
    process.exit(1);
  });
}

module.exports = { main, loadConfig };
