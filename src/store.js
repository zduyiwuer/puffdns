'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const log = require('./util/log');

/** Normalize an owner name: "@", "" and "@.zone" all mean the zone apex. */
function normalizeOwner(name) {
  const n = String(name || '').trim().toLowerCase();
  if (n === '@' || n === '') return '';
  const bare = n.replace(/\.$/, '');
  // "@.example.com" is the apex of that zone
  if (bare === '@' || bare.startsWith('@.')) return '';
  return bare;
}

/** Convert an FQDN to its relative owner name inside a zone. */
function relativeName(name, zone) {
  const n = normalizeOwner(name);
  const z = normalizeOwner(zone);
  if (!z) return n;
  if (n === z) return '';
  if (n.endsWith('.' + z)) return n.slice(0, -(z.length + 1));
  return n;
}

/**
 * Tiny embedded document store. Keeps everything in memory for fast reads and
 * persists to a single JSON file using write-to-temp + atomic rename, so a
 * crash mid-write can never leave a half-written database on disk.
 *
 * Deliberately dependency-free: this app only stores zones, records, users and
 * API keys, which is a few hundred KB at most.
 */
class Store {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.file = path.join(dataDir, 'puffdns.json');
    this.data = null;
    this._writeTimer = null;
    this._dirty = false;
  }

  init(defaults) {
    fs.mkdirSync(this.dataDir, { recursive: true });
    if (fs.existsSync(this.file)) {
      try {
        const raw = fs.readFileSync(this.file, 'utf8');
        this.data = JSON.parse(raw);
        log.info(`loaded store from ${this.file}`);
      } catch (err) {
        const backup = `${this.file}.corrupt-${Date.now()}`;
        log.error(`store file is corrupt (${err.message}); moving to ${backup}`);
        try {
          fs.renameSync(this.file, backup);
        } catch {
          /* best effort */
        }
        this.data = null;
      }
    }

    if (!this.data) {
      this.data = defaults;
      this.flushSync();
      log.info(`initialized new store at ${this.file}`);
    } else {
      // Merge defaults so upgrades pick up new fields
      this.data = { ...defaults, ...this.data };
      this.data.settings = { ...(defaults.settings || {}), ...(this.data.settings || {}) };
    }

    this._reindex();
    return this.data;
  }

  // -------------------------------------------------------------------------
  // Indexes (rebuilt on load, kept in sync on mutation)
  // -------------------------------------------------------------------------
  _reindex() {
    this.zoneMap = new Map(); // zone name -> zone object
    for (const zone of this.data.zones || []) {
      zone.records = zone.records || [];
      this.zoneMap.set(zone.name, zone);
    }
    this.userMap = new Map();
    for (const user of this.data.users || []) {
      this.userMap.set(user.username, user);
    }
  }

  // -------------------------------------------------------------------------
  // Zones
  // -------------------------------------------------------------------------
  listZones() {
    return this.data.zones || [];
  }

  hasZone(name) {
    return this.zoneMap.has(name);
  }

  getZone(name) {
    return this.zoneMap.get(name) || null;
  }

  createZone(zone) {
    this.data.zones.push(zone);
    this.zoneMap.set(zone.name, zone);
    this.markDirty();
    return zone;
  }

  updateZone(name, patch) {
    const zone = this.zoneMap.get(name);
    if (!zone) return null;
    Object.assign(zone, patch, { updatedAt: new Date().toISOString() });
    this.markDirty();
    return zone;
  }

  deleteZone(name) {
    const idx = this.data.zones.findIndex((z) => z.name === name);
    if (idx < 0) return false;
    this.data.zones.splice(idx, 1);
    this.zoneMap.delete(name);
    this.markDirty();
    return true;
  }

  /**
   * Find records matching owner name and type inside a zone.
   *
   * Records are stored under their *relative* owner name ("@", "www",
   * "*.api"), so an FQDN query is normalized to its relative form first.
   * type === null means "any type".
   */
  findRecords(zoneName, name, type) {
    const zone = this.zoneMap.get(zoneName);
    if (!zone) return [];
    const rel = relativeName(normalizeOwner(name), zoneName);
    return zone.records.filter(
      (r) => r.name === rel && (type === null || type === undefined || r.type === type)
    );
  }

  /** Same as findRecords but returns records whose owner is the FQDN. */
  nameExists(zoneName, name) {
    const zone = this.zoneMap.get(zoneName);
    if (!zone) return false;
    const rel = relativeName(normalizeOwner(name), zoneName);
    return zone.records.some((r) => r.name === rel);
  }

  allRecords() {
    let out = [];
    for (const zone of this.data.zones || []) {
      for (const rec of zone.records) out.push({ ...rec, zone: zone.name });
    }
    return out;
  }

  findRecordById(id) {
    for (const zone of this.data.zones || []) {
      const rec = zone.records.find((r) => r.id === id);
      if (rec) return { zone, record: rec };
    }
    return null;
  }

  addRecord(zoneName, record) {
    const zone = this.zoneMap.get(zoneName);
    if (!zone) return null;
    zone.records.push(record);
    zone.updatedAt = new Date().toISOString();
    this.markDirty();
    return record;
  }

  updateRecord(id, patch) {
    const found = this.findRecordById(id);
    if (!found) return null;
    Object.assign(found.record, patch, { updatedAt: new Date().toISOString() });
    found.zone.updatedAt = new Date().toISOString();
    this.markDirty();
    return found.record;
  }

  deleteRecord(id) {
    for (const zone of this.data.zones || []) {
      const idx = zone.records.findIndex((r) => r.id === id);
      if (idx >= 0) {
        const [removed] = zone.records.splice(idx, 1);
        zone.updatedAt = new Date().toISOString();
        this.markDirty();
        return removed;
      }
    }
    return null;
  }

  // -------------------------------------------------------------------------
  // Users & auth
  // -------------------------------------------------------------------------
  listUsers() {
    return this.data.users || [];
  }

  getUser(username) {
    return this.userMap.get(username) || null;
  }

  createUser(user) {
    this.data.users.push(user);
    this.userMap.set(user.username, user);
    this.markDirty();
    return user;
  }

  updateUser(username, patch) {
    const user = this.userMap.get(username);
    if (!user) return null;
    Object.assign(user, patch);
    this.markDirty();
    return user;
  }

  deleteUser(username) {
    const idx = this.data.users.findIndex((u) => u.username === username);
    if (idx < 0) return false;
    this.data.users.splice(idx, 1);
    this.userMap.delete(username);
    this.markDirty();
    return true;
  }

  // -------------------------------------------------------------------------
  // API tokens (for DDNS updates)
  // -------------------------------------------------------------------------
  listTokens() {
    return this.data.tokens || [];
  }

  getToken(id) {
    return (this.data.tokens || []).find((t) => t.id === id) || null;
  }

  getTokenByHash(hash) {
    return (this.data.tokens || []).find((t) => t.hash === hash) || null;
  }

  createToken(token) {
    this.data.tokens.push(token);
    this.markDirty();
    return token;
  }

  updateToken(id, patch) {
    const tok = this.getToken(id);
    if (!tok) return null;
    Object.assign(tok, patch);
    this.markDirty();
    return tok;
  }

  deleteToken(id) {
    const idx = this.data.tokens.findIndex((t) => t.id === id);
    if (idx < 0) return false;
    this.data.tokens.splice(idx, 1);
    this.markDirty();
    return true;
  }

  // -------------------------------------------------------------------------
  // Settings
  // -------------------------------------------------------------------------
  getSettings() {
    return this.data.settings || {};
  }

  updateSettings(patch) {
    this.data.settings = { ...(this.data.settings || {}), ...patch };
    this.markDirty();
    return this.data.settings;
  }

  // -------------------------------------------------------------------------
  // Persistence
  // -------------------------------------------------------------------------
  markDirty() {
    this._dirty = true;
    if (this._writeTimer) return;
    // Coalesce bursts of writes into one flush
    this._writeTimer = setTimeout(() => {
      this._writeTimer = null;
      this.flushSync();
    }, 250);
    if (this._writeTimer.unref) this._writeTimer.unref();
  }

  flushSync() {
    if (!this._dirty) return;
    const tmp = `${this.file}.tmp`;
    try {
      fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2), { mode: 0o600 });
      fs.renameSync(tmp, this.file);
      this._dirty = false;
    } catch (err) {
      log.error('failed to persist store:', err.message);
    }
  }

  close() {
    if (this._writeTimer) {
      clearTimeout(this._writeTimer);
      this._writeTimer = null;
    }
    this.flushSync();
  }
}

// ---------------------------------------------------------------------------
// Password hashing (scrypt) and token helpers
// ---------------------------------------------------------------------------

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const derived = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return { salt, hash: derived };
}

function verifyPassword(password, salt, expectedHash) {
  try {
    const { hash } = hashPassword(password, salt);
    const a = Buffer.from(hash, 'hex');
    const b = Buffer.from(expectedHash, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function generateToken() {
  return crypto.randomBytes(24).toString('base64url');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function newId(prefix = '') {
  return prefix + crypto.randomBytes(8).toString('hex');
}

/** Escape a password for safe storage in a URL query string. */
function escapeToken(token) {
  return encodeURIComponent(token);
}

module.exports = {
  Store,
  hashPassword,
  verifyPassword,
  generateToken,
  hashToken,
  newId,
  escapeToken,
  normalizeOwner,
  relativeName,
};
