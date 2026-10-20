'use strict';

/**
 * Ring buffer of recent DNS queries for the panel's live view.
 * Bounded so memory stays flat under load.
 */
class QueryLog {
  constructor({ size = 1000, enabled = true } = {}) {
    this.size = size;
    this.enabled = enabled;
    this.entries = [];
    this.total = 0;
    this.byType = new Map();
    this.byResponse = new Map();
    this.byClient = new Map();
    this.latencies = [];
    this.startedAt = Date.now();
  }

  add(entry) {
    this.total++;
    if (!this.enabled) return;

    this.entries.push(entry);
    if (this.entries.length > this.size) this.entries.shift();

    this.byType.set(entry.type, (this.byType.get(entry.type) || 0) + 1);
    this.byResponse.set(entry.rcode, (this.byResponse.get(entry.rcode) || 0) + 1);
    this.byClient.set(entry.client, (this.byClient.get(entry.client) || 0) + 1);

    if (entry.rcode !== 'NOERROR' || entry.count === 0) {
      // keep the slow tail only, bounded
      this.latencies.push(entry.ms);
      if (this.latencies.length > 1000) this.latencies.shift();
    }
  }

  recent(limit = 100) {
    return this.entries.slice(-limit).reverse();
  }

  clear() {
    this.entries = [];
  }

  topBy(field, n = 10) {
    const src = field === 'client' ? this.byClient : field === 'type' ? this.byType : this.byResponse;
    return [...src.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, n)
      .map(([key, count]) => ({ key, count }));
  }

  stats() {
    const total = this.total || 1;
    const lat = [...this.latencies].sort((a, b) => a - b);
    const pct = (p) => (lat.length ? lat[Math.min(lat.length - 1, Math.floor((lat.length * p) / 100))] : 0);
    const avg = lat.length ? Math.round(lat.reduce((a, b) => a + b, 0) / lat.length) : 0;

    return {
      total: this.total,
      buffered: this.entries.length,
      bufferSize: this.size,
      enabled: this.enabled,
      uptimeSeconds: Math.floor((Date.now() - this.startedAt) / 1000),
      qps: Number((this.total / Math.max(1, (Date.now() - this.startedAt) / 1000)).toFixed(2)),
      topTypes: this.topBy('type', 8),
      topClients: this.topBy('client', 8),
      topResponses: this.topBy('rcode', 8),
      latency: { avg, p50: pct(50), p95: pct(95), p99: pct(99), max: lat.length ? lat[lat.length - 1] : 0 },
      successRate: Number(
        (((this.byResponse.get('NOERROR') || 0) / total) * 100).toFixed(2)
      ),
    };
  }
}

module.exports = { QueryLog };
