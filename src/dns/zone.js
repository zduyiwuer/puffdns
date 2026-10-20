'use strict';

const { TYPE, TYPE_NAME, MULTI_OK } = require('./types');
const { normalizeName, toLabels, isSubdomain } = require('./packet');

/**
 * Authoritative zone engine: answers queries purely from records held in the
 * data store. Supports wildcards, CNAME chasing inside the zone, delegation
 * via NS records, and automatic SOA/NS synthesis.
 */
class ZoneEngine {
  constructor(store) {
    this.store = store;
  }

  /** Find the longest zone in the store matching qname. */
  findZone(qname) {
    const name = normalizeName(qname);
    const labels = toLabels(name);
    for (let i = 0; i < labels.length; i++) {
      const candidate = labels.slice(i).join('.');
      if (this.store.hasZone(candidate)) return candidate;
    }
    return null;
  }

  /**
   * Look up records for a question within an authoritative zone.
   * Returns { zone, answers: [...], cnames: [...], nodata, nxdomain, extras }
   */
  lookup(qname, qtype) {
    const name = normalizeName(qname);
    const zone = this.findZone(name);
    if (!zone) return null;

    const labels = toLabels(name);
    const zoneLabels = toLabels(zone);

    // Out-of-zone guard (shouldn't happen given findZone, but be safe)
    if (labels.length < zoneLabels.length) return null;
    const relative = labels.slice(0, labels.length - zoneLabels.length).join('.');

    const zoneCfg = this.store.getZone(zone);
    if (!zoneCfg) return null;

    // SOA at the apex is always available
    if (relative === '' && qtype === TYPE.SOA) {
      return {
        zone,
        answers: [this.soaRecord(zoneCfg)],
        cnames: [],
        extras: this.authorityExtras(zoneCfg, name),
        nxdomain: false,
      };
    }

    // NS at the apex: use explicit records, else the zone's configured NS
    if (relative === '' && qtype === TYPE.NS) {
      const explicit = this.store.findRecords(zone, name, TYPE.NS);
      const answers = explicit.length
        ? explicit.map((rec) => this.toRR(rec))
        : zoneCfg.ns.map((ns) => ({
            name,
            type: TYPE.NS,
            ttl: zoneCfg.ttl || 3600,
            data: ns,
          }));
      return { zone, answers, cnames: [], extras: this.authorityExtras(zoneCfg, name), nxdomain: false };
    }

    // Exact match on the full name
    const exact = this.store.findRecords(zone, name, qtype);
    if (exact.length) {
      return this.finishLookup(zoneCfg, zone, name, exact, relative);
    }

    // Wildcard: *.relative.closest-encloser — RFC 1034 §4.3.2
    if (relative.includes('*') === false) {
      const labels2 = relative ? relative.split('.') : [];
      for (let i = 0; i < labels2.length; i++) {
        const wcName = ['*', ...labels2.slice(i)].join('.');
        if (wcName === relative) continue; // already handled by exact match
        const wcFull = wcName ? `${wcName}.${zone}` : zone;
        const wcRecords = this.store.findRecords(zone, wcFull, qtype);
        if (wcRecords.length) {
          // Rewrite the owner name to the queried name per RFC 1034
          const rewritten = wcRecords.map((rec) => ({ ...rec, name }));
          return this.finishLookup(zoneCfg, zone, name, rewritten, relative, true);
        }
      }
    }

    // CNAME handling: a CNAME at the name overrides other types (except RRSIG)
    const cnameRecs = this.store.findRecords(zone, name, TYPE.CNAME);
    if (cnameRecs.length && qtype !== TYPE.CNAME) {
      const cnames = cnameRecs.map((rec) => this.toRR({ ...rec, name }));
      return { zone, answers: [], cnames, extras: [], nxdomain: false, cnameOnly: true };
    }

    // Name exists in zone but no matching type -> NODATA
    if (this.store.nameExists(zone, name)) {
      return { zone, answers: [], cnames: [], extras: this.authorityExtras(zoneCfg, name), nxdomain: false };
    }

    // Wildcard exists but different type: still NODATA if the name matched
    // a wildcard owner.
    const wcOwnerExists = this.wildcardExists(zoneCfg, zone, relative);
    if (wcOwnerExists) {
      return { zone, answers: [], cnames: [], extras: this.authorityExtras(zoneCfg, name), nxdomain: false };
    }

    return { zone, answers: [], cnames: [], extras: this.authorityExtras(zoneCfg, name), nxdomain: true };
  }

  finishLookup(zoneCfg, zone, name, records, relative, viaWildcard = false) {
    const answers = records.map((rec) => this.toRR(rec));

    // Include CNAMEs found alongside the answer (e.g. A query where owner is a CNAME)
    const extras = [];
    if (qtypeNeedsExtra(answers)) {
      // nothing special by default
    }
    return {
      zone,
      answers,
      cnames: [],
      extras: extras.concat(this.authorityExtras(zoneCfg, name, false)),
      nxdomain: false,
      viaWildcard,
    };
  }

  wildcardExists(zoneCfg, zone, relative) {
    if (!relative.includes('*')) {
      const labels2 = relative ? relative.split('.') : [];
      for (let i = 0; i < labels2.length; i++) {
        const wcName = ['*', ...labels2.slice(i)].join('.');
        const wcFull = wcName ? `${wcName}.${zone}` : zone;
        if (this.store.nameExists(zone, wcFull)) return true;
      }
    }
    return false;
  }

  authorityExtras(zoneCfg, name, includeSoa = true) {
    if (!includeSoa) return [];
    return [this.soaRecord(zoneCfg)];
  }

  soaRecord(zoneCfg) {
    const ttl = zoneCfg.ttl || 3600;
    const soa = zoneCfg.soa || {};
    return {
      name: zoneCfg.name,
      type: TYPE.SOA,
      ttl: soa.minimum && soa.minimum > 0 ? Math.min(ttl, soa.minimum) : ttl,
      data: [
        soa.mname || `${zoneCfg.name}.`,
        soa.rname || `hostmaster.${zoneCfg.name}.`,
        soa.serial || 1,
        soa.refresh || 3600,
        soa.retry || 600,
        soa.expire || 604800,
        soa.minimum || 60,
      ].join(' '),
    };
  }

  toRR(rec) {
    return {
      name: normalizeName(rec.name),
      type: rec.type,
      ttl: rec.ttl || 3600,
      data: rec.data,
    };
  }
}

function qtypeNeedsExtra() {
  return false;
}

/** Handle CNAME chains within the zone, adding the final target answers. */
function resolveCnameChain(engine, zone, name, qtype, maxDepth = 8) {
  let current = normalizeName(name);
  const chain = [];
  const seen = new Set();
  const extras = [];

  while (chain.length < maxDepth) {
    if (seen.has(current)) break;
    seen.add(current);

    const cnameRecords = engine.store.findRecords(zone, current, TYPE.CNAME);
    if (!cnameRecords.length) {
      // End of the chain: gather records for the original qtype at this name
      const targets = qtype && qtype !== TYPE.CNAME ? engine.store.findRecords(zone, current, qtype) : [];
      if (targets.length) {
        extras.push(...targets.map((rec) => engine.toRR({ ...rec, name: current })));
      }
      break;
    }

    const rr = engine.toRR(cnameRecords[0]);
    chain.push(rr);
    current = normalizeName(cnameRecords[0].data);
    if (!current) break;
  }

  return { chain, answers: extras, extras: [] };
}

/** Validate a record before it is written to the store. */
function validateRecord(rec) {
  const errors = [];
  const name = normalizeName(rec.name);
  if (name.length > 253) errors.push('name too long');
  for (const label of toLabels(name)) {
    if (label.length > 63) errors.push('label too long');
  }
  if (toLabels(name).some((l) => l === '*' && toLabels(name).indexOf(l) !== 0)) {
    errors.push('wildcard must be the leftmost label');
  }

  const type = rec.type;
  const typeName = TYPE_NAME[type] || type;

  if (type === TYPE.A) {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(String(rec.data).trim())) {
      errors.push('A record needs an IPv4 address');
    } else {
      const parts = String(rec.data).trim().split('.').map(Number);
      if (parts.some((p) => p > 255)) errors.push('invalid IPv4 address');
    }
  } else if (type === TYPE.AAAA) {
    if (!String(rec.data).includes(':')) errors.push('AAAA record needs an IPv6 address');
  } else if (type === TYPE.CNAME || type === TYPE.NS || type === TYPE.PTR || type === TYPE.DNAME) {
    if (!normalizeName(rec.data)) errors.push(`${typeName} needs a target hostname`);
  } else if (type === TYPE.MX) {
    if (!/^\d+\s+\S+$/.test(String(rec.data).trim())) errors.push('MX format: "10 mail.example.com"');
  } else if (type === TYPE.SRV) {
    if (!/^\d+\s+\d+\s+\d+\s+\S+$/.test(String(rec.data).trim())) {
      errors.push('SRV format: "0 5 443 target.example.com"');
    }
  } else if (type === TYPE.SOA) {
    const parts = String(rec.data).trim().split(/\s+/);
    if (parts.length < 7) errors.push('SOA needs 7 space-separated fields');
  } else if (type === TYPE.CAA) {
    const parts = String(rec.data).trim().split(/\s+/);
    if (parts.length < 3) errors.push('CAA format: "0 issue letsencrypt.org"');
  } else if (type === TYPE.TXT || type === TYPE.SPF) {
    if (rec.data === undefined || rec.data === null || String(rec.data).length === 0) {
      errors.push('TXT needs content');
    }
  }

  const ttl = Number(rec.ttl);
  if (!Number.isFinite(ttl) || ttl < 0 || ttl > 2147483647) {
    errors.push('TTL must be between 0 and 2147483647');
  }

  return errors;
}

module.exports = { ZoneEngine, validateRecord, resolveCnameChain, isSubdomain, MULTI_OK };
