'use strict';

const os = require('os');
const log = require('../util/log');
const { TYPE, TYPE_NAME, nameToType, SUPPORTED_TYPES } = require('../dns/types');
const { normalizeName, isIP, isIPv4, isIPv6 } = require('../dns/packet');
const { validateRecord } = require('../dns/zone');
const { hashPassword, verifyPassword, generateToken, hashToken, newId } = require('../store');
const {
  HttpError,
  Router,
  sendJson,
  sendText,
  readJson,
  clientIp,
  parseUrl,
  RateLimiter,
} = require('./http');

const ROLES = { ADMIN: 'admin', OPERATOR: 'operator', VIEWER: 'viewer' };

/**
 * Build the management API. Everything except /api/login and /api/health
 * requires an authenticated session.
 */
function createApi({ store, config, dnsServer, upstream, cache, zoneEngine, session, queryLog, accessControl }) {
  const router = new Router();
  const loginLimiter = new RateLimiter({ max: 8, windowMs: 5 * 60 * 1000 });

  // -------------------------------------------------------------------------
  // helpers
  // -------------------------------------------------------------------------
  const requireAuth = (req) => {
    const sess = session.fromRequest(req);
    if (!sess) throw new HttpError(401, 'authentication required');
    const user = store.getUser(sess.username);
    if (!user) throw new HttpError(401, 'user no longer exists');
    return user;
  };

  const requireRole = (req, roles) => {
    const user = requireAuth(req);
    if (!roles.includes(user.role)) {
      throw new HttpError(403, `requires role: ${roles.join(' or ')}`);
    }
    return user;
  };

  const publicZone = (zone) => ({
    name: zone.name,
    type: zone.type || 'master',
    ttl: zone.ttl,
    soa: zone.soa,
    ns: zone.ns,
    recordCount: zone.records.length,
    createdAt: zone.createdAt,
    updatedAt: zone.updatedAt,
  });

  const publicRecord = (rec) => ({
    id: rec.id,
    zone: rec.zone,
    name: rec.name,
    type: TYPE_NAME[rec.type] || rec.type,
    typeCode: rec.type,
    data: rec.data,
    ttl: rec.ttl,
    note: rec.note || '',
    createdAt: rec.createdAt,
    updatedAt: rec.updatedAt,
  });

  const bumpSerial = (zone) => {
    const soa = zone.soa || {};
    soa.serial = (Number(soa.serial) || 0) + 1;
    zone.soa = soa;
    store.updateZone(zone.name, { soa });
  };

  // -------------------------------------------------------------------------
  // health & meta
  // -------------------------------------------------------------------------
  router.get(
    '/api/health',
    async (req, res) => {
      sendJson(res, 200, {
        status: 'ok',
        uptime: Math.floor(process.uptime()),
        version: require('../../package.json').version,
        zones: store.listZones().length,
        records: store.allRecords().length,
        queries: dnsServer.stats.queries,
        cache: cache.stats(),
        ports: {
          dns: config.dnsPort,
          web: config.webPort,
          doh: `${config.webPort}/dns-query`,
        },
      });
    },
    { public: true }
  );

  router.get(
    '/api/meta',
    async (req, res) => {
      requireAuth(req);
      sendJson(res, 200, {
        recordTypes: SUPPORTED_TYPES,
        defaults: {
          ttl: config.defaultTtl,
        },
        zones: store.listZones().length,
        records: store.allRecords().length,
        stats: dnsServer.getStats(),
        queryLog: queryLog.stats(),
        upstream: upstream.upstreams,
        system: {
          hostname: os.hostname(),
          platform: `${os.platform()} ${os.release()}`,
          nodeVersion: process.version,
          memoryMB: Math.round(process.memoryUsage().rss / 1024 / 1024),
          cpus: os.cpus().length,
        },
      });
    },
    { public: false }
  );

  // -------------------------------------------------------------------------
  // auth
  // -------------------------------------------------------------------------
  router.post(
    '/api/login',
    async (req, res) => {
      const ip = clientIp(req);
      const limit = loginLimiter.check(ip);
      if (!limit.allowed) {
        throw new HttpError(429, 'too many login attempts, try again later');
      }
      const body = await readJson(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      if (!username || !password) throw new HttpError(400, 'username and password are required');

      const user = store.getUser(username);
      if (!user || !verifyPassword(password, user.salt, user.hash)) {
        log.warn(`failed login for "${username}" from ${ip}`);
        throw new HttpError(401, 'invalid credentials');
      }

      loginLimiter.reset(ip);
      const token = session.sign({ username: user.username, role: user.role });
      log.info(`${user.username} logged in from ${ip}`);
      sendJson(
        res,
        200,
        { ok: true, user: { username: user.username, role: user.role, email: user.email || '' } },
        { 'Set-Cookie': session.cookieHeader(token) }
      );
    },
    { public: true }
  );

  router.post(
    '/api/logout',
    async (req, res) => {
      sendJson(res, 200, { ok: true }, { 'Set-Cookie': session.cookieHeader('', { clear: true }) });
    },
    { public: true }
  );

  router.get(
    '/api/me',
    async (req, res) => {
      const user = requireAuth(req);
      sendJson(res, 200, {
        username: user.username,
        role: user.role,
        email: user.email || '',
        createdAt: user.createdAt,
        lastLogin: user.lastLogin,
      });
    },
    { public: false }
  );

  router.post(
    '/api/me/password',
    async (req, res) => {
      const user = requireAuth(req);
      const body = await readJson(req);
      const current = String(body.currentPassword || '');
      const next = String(body.newPassword || '');
      if (!verifyPassword(current, user.salt, user.hash)) {
        throw new HttpError(403, 'current password is incorrect');
      }
      if (next.length < 8) throw new HttpError(400, 'new password must be at least 8 characters');
      const { salt, hash } = hashPassword(next);
      store.updateUser(user.username, { salt, hash, passwordChangedAt: new Date().toISOString() });
      log.info(`${user.username} changed their password`);
      sendJson(res, 200, { ok: true });
    },
    { public: false }
  );

  // -------------------------------------------------------------------------
  // users (admin only)
  // -------------------------------------------------------------------------
  router.get(
    '/api/users',
    async (req, res) => {
      requireRole(req, [ROLES.ADMIN]);
      sendJson(
        res,
        200,
        store.listUsers().map((u) => ({
          username: u.username,
          role: u.role,
          email: u.email || '',
          createdAt: u.createdAt,
          lastLogin: u.lastLogin || null,
        }))
      );
    },
    { public: false }
  );

  router.post(
    '/api/users',
    async (req, res) => {
      requireRole(req, [ROLES.ADMIN]);
      const body = await readJson(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      const role = String(body.role || ROLES.VIEWER);

      if (!/^[a-zA-Z0-9._-]{3,32}$/.test(username)) {
        throw new HttpError(400, 'username must be 3-32 chars of letters, digits, dot, dash or underscore');
      }
      if (password.length < 8) throw new HttpError(400, 'password must be at least 8 characters');
      if (!Object.values(ROLES).includes(role)) throw new HttpError(400, `role must be one of ${Object.values(ROLES).join(', ')}`);
      if (store.getUser(username)) throw new HttpError(409, 'user already exists');

      const { salt, hash } = hashPassword(password);
      const user = store.createUser({
        username,
        salt,
        hash,
        role,
        email: String(body.email || '').trim(),
        createdAt: new Date().toISOString(),
      });
      log.info(`user ${username} created with role ${role}`);
      sendJson(res, 201, { username: user.username, role: user.role, email: user.email });
    },
    { public: false }
  );

  router.delete(
    '/api/users/:username',
    async (req, res) => {
      const admin = requireRole(req, [ROLES.ADMIN]);
      const { username } = req.params;
      if (username === admin.username) throw new HttpError(400, 'cannot delete your own account');
      if (!store.getUser(username)) throw new HttpError(404, 'user not found');
      store.deleteUser(username);
      log.info(`user ${username} deleted by ${admin.username}`);
      sendJson(res, 200, { ok: true });
    },
    { public: false }
  );

  // -------------------------------------------------------------------------
  // zones
  // -------------------------------------------------------------------------
  router.get(
    '/api/zones',
    async (req, res) => {
      requireAuth(req);
      sendJson(res, 200, store.listZones().map(publicZone));
    },
    { public: false }
  );

  router.post(
    '/api/zones',
    async (req, res) => {
      requireRole(req, [ROLES.ADMIN, ROLES.OPERATOR]);
      const body = await readJson(req);
      const name = normalizeName(body.name || '');
      if (!name) throw new HttpError(400, 'zone name is required');
      if (store.hasZone(name)) throw new HttpError(409, 'zone already exists');
      if (!/^[a-z0-9]([a-z0-9-_.]*[a-z0-9])?$/.test(name) || !name.includes('.')) {
        throw new HttpError(400, 'invalid zone name (use a FQDN such as example.com)');
      }

      const ttl = Number(body.ttl) || config.defaultTtl;
      const ns = Array.isArray(body.ns) && body.ns.length ? body.ns.map(normalizeName).filter(Boolean) : [`ns1.${name}`];
      const soa = {
        mname: normalizeName(body.mname || ns[0]),
        rname: normalizeName(body.rname || `hostmaster.${name}`),
        serial: Number(body.serial) || Math.floor(Date.now() / 1000) % 1000000000,
        refresh: Number(body.refresh) || 3600,
        retry: Number(body.retry) || 600,
        expire: Number(body.expire) || 604800,
        minimum: Number(body.minimum) || 60,
      };

      const zone = store.createZone({
        name,
        type: 'master',
        ttl,
        ns,
        soa,
        records: [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
      cache.invalidateZone(name);
      log.info(`zone ${name} created`);
      sendJson(res, 201, publicZone(zone));
    },
    { public: false }
  );

  router.get(
    '/api/zones/:name',
    async (req, res) => {
      requireAuth(req);
      const zone = store.getZone(req.params.name);
      if (!zone) throw new HttpError(404, 'zone not found');
      sendJson(res, 200, {
        ...publicZone(zone),
        records: zone.records
          .slice()
          .sort((a, b) => a.name.localeCompare(b.name) || a.type - b.type)
          .map(publicRecord),
      });
    },
    { public: false }
  );

  router.put(
    '/api/zones/:name',
    async (req, res) => {
      requireRole(req, [ROLES.ADMIN, ROLES.OPERATOR]);
      const zone = store.getZone(req.params.name);
      if (!zone) throw new HttpError(404, 'zone not found');
      const body = await readJson(req);

      const patch = {};
      if (body.ttl !== undefined) patch.ttl = Number(body.ttl) || zone.ttl;
      if (body.ns !== undefined) {
        const ns = Array.isArray(body.ns) ? body.ns.map(normalizeName).filter(Boolean) : [];
        if (!ns.length) throw new HttpError(400, 'at least one NS host is required');
        patch.ns = ns;
      }
      if (body.soa !== undefined) patch.soa = { ...zone.soa, ...body.soa };

      const updated = store.updateZone(zone.name, patch);
      bumpSerial(updated);
      cache.invalidateZone(zone.name);
      log.info(`zone ${zone.name} updated`);
      sendJson(res, 200, publicZone(updated));
    },
    { public: false }
  );

  router.delete(
    '/api/zones/:name',
    async (req, res) => {
      requireRole(req, [ROLES.ADMIN]);
      const zone = store.getZone(req.params.name);
      if (!zone) throw new HttpError(404, 'zone not found');
      store.deleteZone(zone.name);
      cache.invalidateZone(zone.name);
      log.info(`zone ${zone.name} deleted`);
      sendJson(res, 200, { ok: true });
    },
    { public: false }
  );

  // -------------------------------------------------------------------------
  // records
  // -------------------------------------------------------------------------
  router.post(
    '/api/zones/:name/records',
    async (req, res) => {
      requireRole(req, [ROLES.ADMIN, ROLES.OPERATOR]);
      const zone = store.getZone(req.params.name);
      if (!zone) throw new HttpError(404, 'zone not found');

      const body = await readJson(req);
      const name = normalizeName(body.name === '@' || !body.name ? '' : body.name);
      const typeName = String(body.type || '').toUpperCase();
      const type = nameToType(typeName);
      if (!type) throw new HttpError(400, `unknown record type: ${body.type}`);
      if (!SUPPORTED_TYPES.includes(TYPE_NAME[type])) {
        throw new HttpError(400, `type ${TYPE_NAME[type]} is not supported`);
      }
      const ttl = Number(body.ttl) || zone.ttl || config.defaultTtl;

      const record = {
        id: newId('rec_'),
        name,
        type,
        data: String(body.data || '').trim(),
        ttl,
        note: String(body.note || '').slice(0, 200),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      const errors = validateRecord(record);
      if (errors.length) throw new HttpError(400, errors.join('; '), { errors });

      // Duplicate detection
      const duplicate = zone.records.find(
        (r) => r.name === record.name && r.type === record.type && r.data === record.data
      );
      if (duplicate) {
        throw new HttpError(409, 'an identical record already exists');
      }
      // CNAME must be unique per name
      if (record.type === TYPE.CNAME) {
        const existingCname = zone.records.find((r) => r.name === record.name && r.type === TYPE.CNAME);
        if (existingCname) {
          throw new HttpError(409, 'a CNAME already exists at this name; delete it first');
        }
      }

      store.addRecord(zone.name, record);
      bumpSerial(zone);
      cache.invalidate(zone.name === '' ? '.' : `${record.name}.${zone.name}`.replace(/^\./, ''));
      if (record.name === '') cache.invalidate(zone.name);
      log.info(`record added ${record.name || '@'}.${zone.name} ${TYPE_NAME[record.type]} -> ${record.data}`);
      sendJson(res, 201, publicRecord({ ...record, zone: zone.name }));
    },
    { public: false }
  );

  router.put(
    '/api/records/:id',
    async (req, res) => {
      requireRole(req, [ROLES.ADMIN, ROLES.OPERATOR]);
      const found = store.findRecordById(req.params.id);
      if (!found) throw new HttpError(404, 'record not found');

      const body = await readJson(req);
      const patch = {};
      if (body.name !== undefined) patch.name = normalizeName(body.name === '@' ? '' : body.name);
      if (body.data !== undefined) patch.data = String(body.data).trim();
      if (body.ttl !== undefined) patch.ttl = Number(body.ttl) || found.record.ttl;
      if (body.note !== undefined) patch.note = String(body.note).slice(0, 200);
      if (body.type !== undefined) {
        const type = nameToType(body.type);
        if (!type || !SUPPORTED_TYPES.includes(TYPE_NAME[type])) {
          throw new HttpError(400, `unsupported record type: ${body.type}`);
        }
        patch.type = type;
      }

      const candidate = { ...found.record, ...patch };
      const errors = validateRecord(candidate);
      if (errors.length) throw new HttpError(400, errors.join('; '), { errors });

      const updated = store.updateRecord(req.params.id, patch);
      bumpSerial(found.zone);
      cache.invalidateZone(found.zone.name);
      log.info(`record ${req.params.id} updated in zone ${found.zone.name}`);
      sendJson(res, 200, publicRecord({ ...updated, zone: found.zone.name }));
    },
    { public: false }
  );

  router.delete(
    '/api/records/:id',
    async (req, res) => {
      requireRole(req, [ROLES.ADMIN, ROLES.OPERATOR]);
      const found = store.findRecordById(req.params.id);
      if (!found) throw new HttpError(404, 'record not found');
      store.deleteRecord(req.params.id);
      bumpSerial(found.zone);
      cache.invalidateZone(found.zone.name);
      log.info(`record ${req.params.id} deleted from zone ${found.zone.name}`);
      sendJson(res, 200, { ok: true });
    },
    { public: false }
  );

  // bulk import / export
  router.post(
    '/api/zones/:name/import',
    async (req, res) => {
      requireRole(req, [ROLES.ADMIN, ROLES.OPERATOR]);
      const zone = store.getZone(req.params.name);
      if (!zone) throw new HttpError(404, 'zone not found');

      const body = await readJson(req);
      const lines = Array.isArray(body.lines) ? body.lines : [];
      const replace = !!body.replace;
      const added = [];
      const errors = [];

      if (replace) {
        zone.records = [];
      }

      lines.forEach((raw, index) => {
        const line = String(raw).trim();
        if (!line || line.startsWith(';')) return;
        const parsed = parseZoneLine(line, zone.name, zone.ttl || 300);
        if (parsed.error) {
          errors.push({ line: index + 1, text: line, error: parsed.error });
          return;
        }
        const record = {
          id: newId('rec_'),
          ...parsed.record,
          note: '',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
        zone.records.push(record);
        added.push(record);
      });

      bumpSerial(zone);
      cache.invalidateZone(zone.name);
      store.markDirty();
      log.info(`imported ${added.length} records into ${zone.name} (${errors.length} errors)`);
      sendJson(res, 200, { added: added.length, errors, records: zone.records.map((r) => publicRecord({ ...r, zone: zone.name })) });
    },
    { public: false }
  );

  router.get(
    '/api/zones/:name/export',
    async (req, res) => {
      requireAuth(req);
      const zone = store.getZone(req.params.name);
      if (!zone) throw new HttpError(404, 'zone not found');
      const lines = zoneToZoneFile(zone);
      sendText(res, 200, lines.join('\n') + '\n', 'text/plain; charset=utf-8');
    },
    { public: false }
  );

  // -------------------------------------------------------------------------
  // DDNS tokens
  // -------------------------------------------------------------------------
  router.get(
    '/api/tokens',
    async (req, res) => {
      requireAuth(req);
      sendJson(
        res,
        200,
        store.listTokens().map((t) => ({
          id: t.id,
          name: t.name,
          zone: t.zone || '',
          hostname: t.hostname || '',
          lastUsed: t.lastUsed || null,
          useCount: t.useCount || 0,
          createdAt: t.createdAt,
          preview: `${t.token.slice(0, 6)}…${t.token.slice(-4)}`,
        }))
      );
    },
    { public: false }
  );

  router.post(
    '/api/tokens',
    async (req, res) => {
      const user = requireRole(req, [ROLES.ADMIN, ROLES.OPERATOR]);
      const body = await readJson(req);
      const zone = normalizeName(body.zone || '');
      const hostname = normalizeName(body.hostname || '');
      const name = String(body.name || '').trim() || `${hostname || '*'}.${zone || '*'}`;

      if (zone && !store.hasZone(zone)) throw new HttpError(400, `zone ${zone} does not exist`);
      if (!zone) throw new HttpError(400, 'a zone is required for a DDNS token');

      const token = generateToken();
      const record = store.createToken({
        id: newId('tok_'),
        name,
        zone,
        hostname,
        token,
        hash: hashToken(token),
        owner: user.username,
        useCount: 0,
        lastUsed: null,
        createdAt: new Date().toISOString(),
      });

      log.info(`DDNS token "${name}" created by ${user.username} for ${hostname || '*'}.${zone}`);
      // The plaintext token is returned exactly once
      sendJson(res, 201, {
        id: record.id,
        name: record.name,
        zone: record.zone,
        hostname: record.hostname,
        token: record.token,
        createdAt: record.createdAt,
      });
    },
    { public: false }
  );

  router.delete(
    '/api/tokens/:id',
    async (req, res) => {
      requireRole(req, [ROLES.ADMIN, ROLES.OPERATOR]);
      const tok = store.getToken(req.params.id);
      if (!tok) throw new HttpError(404, 'token not found');
      store.deleteToken(req.params.id);
      log.info(`DDNS token ${tok.name} deleted`);
      sendJson(res, 200, { ok: true });
    },
    { public: false }
  );

  /**
   * Public DDNS update endpoint. Compatible with the common
   * `?hostname=...&token=...&ipv4=...` shape used by most ddns clients.
   */
  router.get(
    '/api/ddns/update',
    async (req, res) => {
      handleDdnsUpdate(req, res, { store, cache, log });
    },
    { public: true }
  );

  router.post(
    '/api/ddns/update',
    async (req, res) => {
      handleDdnsUpdate(req, res, { store, cache, log });
    },
    { public: true }
  );

  // -------------------------------------------------------------------------
  // settings & access control
  // -------------------------------------------------------------------------
  router.get(
    '/api/settings',
    async (req, res) => {
      requireRole(req, [ROLES.ADMIN]);
      sendJson(res, 200, {
        ...store.getSettings(),
        dnsPort: config.dnsPort,
        webPort: config.webPort,
        accessRules: accessControl.rules,
      });
    },
    { public: false }
  );

  router.put(
    '/api/settings',
    async (req, res) => {
      requireRole(req, [ROLES.ADMIN]);
      const body = await readJson(req);
      const patch = {};

      if (body.upstreams !== undefined) {
        if (!Array.isArray(body.upstreams) || !body.upstreams.length) {
          throw new HttpError(400, 'at least one upstream is required');
        }
        patch.upstreams = upstream.setUpstreams(body.upstreams);
      }
      if (body.cacheEnabled !== undefined) patch.cacheEnabled = !!body.cacheEnabled;
      if (body.cacheMaxEntries !== undefined) patch.cacheMaxEntries = Number(body.cacheMaxEntries) || 20000;
      if (body.defaultTtl !== undefined) patch.defaultTtl = Number(body.defaultTtl) || 300;
      if (body.queryLogEnabled !== undefined) patch.queryLogEnabled = !!body.queryLogEnabled;
      if (body.queryLogSize !== undefined) patch.queryLogSize = Math.min(100000, Number(body.queryLogSize) || 1000);
      if (body.accessRules !== undefined) {
        if (!Array.isArray(body.accessRules)) throw new HttpError(400, 'accessRules must be an array');
        for (const rule of body.accessRules) {
          if (!rule || !rule.cidr) throw new HttpError(400, 'each access rule needs a cidr');
        }
        accessControl.setRules(body.accessRules);
        patch.accessRules = body.accessRules;
      }

      const settings = store.updateSettings(patch);
      // Apply live-tunable options
      if (settings.cacheEnabled !== undefined) config.cacheEnabled = settings.cacheEnabled;
      if (settings.defaultTtl !== undefined) config.defaultTtl = settings.defaultTtl;
      log.info('settings updated:', Object.keys(patch).join(', '));
      sendJson(res, 200, settings);
    },
    { public: false }
  );

  // -------------------------------------------------------------------------
  // query log
  // -------------------------------------------------------------------------
  router.get(
    '/api/queries',
    async (req, res) => {
      requireRole(req, [ROLES.ADMIN]);
      const url = parseUrl(req);
      const limit = Math.min(1000, Number(url.searchParams.get('limit')) || 100);
      sendJson(res, 200, {
        entries: queryLog.recent(limit),
        stats: queryLog.stats(),
      });
    },
    { public: false }
  );

  router.delete(
    '/api/queries',
    async (req, res) => {
      requireRole(req, [ROLES.ADMIN]);
      queryLog.clear();
      sendJson(res, 200, { ok: true });
    },
    { public: false }
  );

  return router;
}

// ---------------------------------------------------------------------------
// DDNS update handling
// ---------------------------------------------------------------------------
async function handleDdnsUpdate(req, res, { store, cache, log }) {
  const url = parseUrl(req);
  const tokenStr = url.searchParams.get('token') || '';
  const hostnameInput = url.searchParams.get('hostname') || url.searchParams.get('host') || '';

  const respond = (code, message, extra = {}) => {
    sendJson(res, code, { ok: code < 400, message, ...extra });
  };

  if (!tokenStr) return respond(401, 'missing token');
  const record = store.getTokenByHash(hashToken(tokenStr));
  if (!record) {
    log.warn(`DDNS update rejected: unknown token from ${clientIp(req)}`);
    return respond(401, 'invalid token');
  }

  // Resolve the target name. Tokens may pin a specific hostname; a caller may
  // pass it fully qualified or relative, so compare both forms.
  const requested = normalizeName(hostnameInput || record.hostname || '');
  if (!requested) return respond(400, 'hostname is required');

  const pinned = normalizeName(record.hostname || '');
  if (pinned) {
    const requestedRel = requested === record.zone ? '' : requested.endsWith(`.${record.zone}`) ? requested.slice(0, -(record.zone.length + 1)) : requested;
    if (requested !== pinned && requestedRel !== pinned) {
      return respond(403, `this token is restricted to ${pinned}`);
    }
  }

  const hostname = requested;

  let zoneName = record.zone;
  if (!zoneName) {
    // derive the zone by walking up the labels
    const labels = hostname.split('.');
    for (let i = 0; i < labels.length - 1; i++) {
      const candidate = labels.slice(i).join('.');
      if (store.hasZone(candidate)) {
        zoneName = candidate;
        break;
      }
    }
  }
  if (!zoneName || !store.hasZone(zoneName)) {
    return respond(404, `no zone found for ${hostname}`);
  }
  const zone = store.getZone(zoneName);
  if (hostname !== zoneName && !hostname.endsWith(`.${zoneName}`)) {
    return respond(400, `${hostname} is not inside ${zoneName}`);
  }
  // Work with the relative owner name inside the zone
  const owner = hostname === zoneName ? '' : hostname.slice(0, -(zoneName.length + 1));

  // Gather desired addresses
  const ipv4 = url.searchParams.get('ipv4') || url.searchParams.get('ip') || '';
  const ipv6 = url.searchParams.get('ipv6') || url.searchParams.get('ip6') || '';
  const clearAll = url.searchParams.get('clear') === 'true';

  if (clearAll) {
    for (const rec of [...zone.records]) {
      if (rec.name === owner && (rec.type === TYPE.A || rec.type === TYPE.AAAA)) {
        store.deleteRecord(rec.id);
      }
    }
    cache.invalidateZone(zoneName);
    log.info(`DDNS cleared ${owner || '@'}.${zoneName} via token ${record.name}`);
    return respond(200, 'records cleared', { zone: zoneName, hostname: owner || '@' });
  }

  const changes = [];
  const errors = [];

  const apply = (value, type, label) => {
    if (!value) return;
    const isV4 = type === TYPE.A;
    if (isV4 ? !isIPv4(value) : !isIPv6(value)) {
      errors.push(`invalid ${label} address: ${value}`);
      return;
    }
    const existing = zone.records.find((r) => r.name === owner && r.type === type);
    if (existing) {
      if (existing.data === value) {
        changes.push({ type: TYPE_NAME[type], action: 'unchanged', data: value });
      } else {
        store.updateRecord(existing.id, { data: value });
        changes.push({ type: TYPE_NAME[type], action: 'updated', data: value });
      }
    } else {
      store.addRecord(zoneName, {
        id: newId('rec_'),
        name: owner,
        type,
        data: value,
        ttl: zone.ttl || 300,
        note: 'updated by DDNS token',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
      changes.push({ type: TYPE_NAME[type], action: 'created', data: value });
    }
  };

  apply(ipv4, TYPE.A, 'IPv4');
  apply(ipv6, TYPE.AAAA, 'IPv6');

  if (errors.length) return respond(400, errors.join('; '), { errors });
  if (!changes.length) return respond(200, 'nothing to update: supply ipv4 and/or ipv6', { zone: zoneName });

  cache.invalidateZone(zoneName);
  store.updateToken(record.id, { lastUsed: new Date().toISOString(), useCount: (record.useCount || 0) + 1 });

  const fqdn = `${owner ? owner + '.' : ''}${zoneName}`;
  log.info(`DDNS updated ${fqdn}: ${changes.map((c) => `${c.type}=${c.data}(${c.action})`).join(' ')}`);
  respond(200, `${fqdn} updated`, { zone: zoneName, hostname: owner || '@', fqdn, changes });
}

// ---------------------------------------------------------------------------
// Zone file helpers
// ---------------------------------------------------------------------------
/**
 * Parse one zone-file line.
 *
 * Accepts `name [ttl] [class] type data`, with the TTL and class both optional
 * (the zone's $TTL and the implicit IN class apply). Trailing `;` comments are
 * stripped.
 */
function parseZoneLine(line, zoneName, defaultTtl = 300) {
  const text = String(line).split(';')[0].trim();
  if (!text) return { error: 'empty line' };

  let parts = text.split(/\s+/).filter(Boolean);
  if (parts.length < 3) return { error: 'expected: name [ttl] [IN] type data' };

  const rawName = parts[0];
  let ttl = defaultTtl;

  if (/^\d+$/.test(parts[1])) {
    ttl = Number(parts[1]);
    parts = parts.slice(1);
  }

  // Drop an explicit class token (IN, CH, HS, ANY) if present
  if (['IN', 'CH', 'HS', 'ANY'].includes(parts[1].toUpperCase())) {
    parts = parts.slice(1);
  }

  const typeStr = parts[1];
  const data = parts.slice(2).join(' ');
  if (!typeStr || !data) return { error: 'missing record type or data' };

  const name = rawName === '@' ? '' : normalizeName(rawName);
  const type = nameToType(typeStr.toUpperCase());
  if (!type) return { error: `unknown type ${typeStr}` };
  if (type === TYPE.SOA || type === TYPE.OPT) return { error: `${typeStr} records cannot be imported here` };
  if (!SUPPORTED_TYPES.includes(TYPE_NAME[type])) return { error: `${typeStr} is not a supported record type` };

  const record = { name, type, data, ttl };
  const errors = validateRecord(record);
  if (errors.length) return { error: errors.join('; ') };
  return { record };
}

function zoneToZoneFile(zone) {
  const soa = zone.soa || {};
  const lines = [
    `; zone file for ${zone.name}`,
    `; exported by puffdns`,
    `$ORIGIN ${zone.name}.`,
    `$TTL ${zone.ttl}`,
    `${zone.name}. IN SOA ${soa.mname || `ns1.${zone.name}`} ${soa.rname || `hostmaster.${zone.name}`} ${
      soa.serial || 1
    } ${soa.refresh || 3600} ${soa.retry || 600} ${soa.expire || 604800} ${soa.minimum || 60}`,
  ];
  for (const ns of zone.ns || []) {
    lines.push(`${zone.name}. IN NS ${ns}`);
  }
  for (const rec of zone.records) {
    const name = rec.name === '' ? '@' : rec.name;
    lines.push(`${name} ${rec.ttl} IN ${TYPE_NAME[rec.type] || rec.type} ${rec.data}`);
  }
  return lines;
}

module.exports = { createApi, ROLES, parseZoneLine, zoneToZoneFile };
