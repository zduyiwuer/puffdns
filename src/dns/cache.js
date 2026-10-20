'use strict';

/**
 * Bounded TTL cache with LRU eviction and negative caching support.
 * Used for both upstream answers and locally served records.
 */
class DnsCache {
  constructor({ maxEntries = 20000, minTtl = 0, maxTtl = 86400 } = {}) {
    this.maxEntries = maxEntries;
    this.minTtl = minTtl;
    this.maxTtl = maxTtl;
    this.map = new Map(); // key -> { value, expiresAt, storedAt, hits }
    this.hits = 0;
    this.misses = 0;
    this.evictions = 0;
    this._timer = null;
  }

  static key(qname, qtype, doBit = false, dnssecOk = false) {
    return `${qname}|${qtype}|${doBit ? 1 : 0}|${dnssecOk ? 1 : 0}`;
  }

  get(qname, qtype, opts = {}) {
    const k = DnsCache.key(qname, qtype, opts.doBit, opts.dnssecOk);
    const entry = this.map.get(k);
    if (!entry) {
      this.misses++;
      return null;
    }
    if (entry.expiresAt <= Date.now()) {
      this.map.delete(k);
      this.misses++;
      return null;
    }
    // LRU: refresh insertion order
    this.map.delete(k);
    this.map.set(k, entry);
    entry.hits++;
    this.hits++;
    return entry.value;
  }

  set(qname, qtype, value, ttl, opts = {}) {
    const k = DnsCache.key(qname, qtype, opts.doBit, opts.dnssecOk);
    let t = Number(ttl);
    if (!Number.isFinite(t) || t <= 0) t = this.minTtl || 1;
    t = Math.min(t, this.maxTtl);
    if (this.map.size >= this.maxEntries) this._evictOldest();
    this.map.set(k, {
      value,
      ttl: t,
      expiresAt: Date.now() + t * 1000,
      storedAt: Date.now(),
      hits: 0,
    });
  }

  _evictOldest() {
    const oldest = this.map.keys().next();
    if (!oldest.done) {
      this.map.delete(oldest.value);
      this.evictions++;
    }
  }

  invalidate(qname, qtype) {
    if (qname === undefined || qname === null) {
      this.map.clear();
      return;
    }
    if (qtype === undefined || qtype === null) {
      for (const k of [...this.map.keys()]) {
        if (k.startsWith(`${qname}|`)) this.map.delete(k);
      }
      return;
    }
    this.map.delete(DnsCache.key(qname, qtype, false, false));
  }

  /**
   * Return an entry even if its TTL has lapsed. Used to keep serving answers
   * when every upstream is unreachable (RFC 8767 style serve-stale).
   */
  getStale(qname, qtype, maxStaleSeconds = 3600) {
    const entry = this.map.get(DnsCache.key(qname, qtype, false, false));
    if (!entry) return null;
    if (Date.now() - entry.expiresAt > maxStaleSeconds * 1000) {
      this.map.delete(DnsCache.key(qname, qtype, false, false));
      return null;
    }
    return entry.value;
  }

  /** Purge every entry whose owner name sits inside the given zone. */
  invalidateZone(zone) {
    const z = String(zone || '').toLowerCase().replace(/\.$/, '');
    if (!z) {
      this.map.clear();
      return;
    }
    for (const k of [...this.map.keys()]) {
      const name = k.split('|')[0];
      if (name === z || name.endsWith(`.${z}`)) this.map.delete(k);
    }
  }

  flush() {
    this.map.clear();
  }

  stats() {
    return {
      entries: this.map.size,
      maxEntries: this.maxEntries,
      hits: this.hits,
      misses: this.misses,
      evictions: this.evictions,
      hitRate: this.hits + this.misses > 0 ? this.hits / (this.hits + this.misses) : 0,
    };
  }

  /** Periodically drop expired entries so memory does not creep. */
  startGc(intervalMs = 60000) {
    if (this._timer) return;
    this._timer = setInterval(() => this.gc(), intervalMs);
    if (this._timer.unref) this._timer.unref();
  }

  stopGc() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }

  gc() {
    const now = Date.now();
    for (const [k, v] of [...this.map.entries()]) {
      if (v.expiresAt <= now) this.map.delete(k);
    }
  }
}

module.exports = { DnsCache };
