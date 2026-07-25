const TTL_BY_CLASS: Record<string, number> = {
  short: 300,
  medium: 3600,
  long: 86400,
};

/**
 * Minimal cache contract used by the verifier. Implementations may be
 * in-process or distributed, but must preserve deterministic keys and
 * bounded expiry semantics.
 */
export interface DecisionCache {
  set(key: string, value: unknown, ttlClass?: string): void;
  get(key: string): unknown | undefined;
  invalidate(key: string): void;
}

interface CacheEntry {
  value: unknown;
  cachedAt: number;
  expiresAt: number;
  ttlClass: string;
}

/** Explicit cache-disabled adapter for live-only deployments and tests. */
export class NoOpDecisionCache implements DecisionCache {
  set(_key: string, _value: unknown, _ttlClass = "medium"): void {
    return undefined;
  }

  get(_key: string): undefined {
    return undefined;
  }

  invalidate(_key: string): void {
    return undefined;
  }
}

export interface CacheStats {
  entries: number;
  maxsize: number;
  hits: number;
  misses: number;
  evictions: number;
  expirations: number;
  hit_ratio: number;
}

/**
 * Bounded LRU cache with simple operational metrics. This is an L1 reference
 * adapter. Production deployments may replace it with a shared L2
 * implementation that satisfies DecisionCache. Node is single-threaded, so
 * unlike the Python TTLCache this needs no lock.
 */
export class TTLCache implements DecisionCache {
  readonly maxsize: number;
  private store: Map<string, CacheEntry> = new Map();
  private hits = 0;
  private misses = 0;
  private evictions = 0;
  private expirations = 0;

  constructor(maxsize = 1024) {
    if (maxsize < 1) {
      throw new Error("maxsize must be at least 1");
    }
    this.maxsize = maxsize;
  }

  get cache(): Map<string, CacheEntry> {
    return this.store;
  }

  private purgeExpired(): void {
    const now = Date.now() / 1000;
    for (const [key, entry] of this.store) {
      if (now > entry.expiresAt) {
        this.store.delete(key);
        this.expirations += 1;
      }
    }
  }

  private evictIfNeeded(): void {
    this.purgeExpired();
    while (this.store.size > this.maxsize) {
      const oldestKey = this.store.keys().next().value;
      if (oldestKey === undefined) break;
      this.store.delete(oldestKey);
      this.evictions += 1;
    }
  }

  set(key: string, value: unknown, ttlClass = "medium"): void {
    const ttlSeconds = TTL_BY_CLASS[ttlClass] ?? TTL_BY_CLASS.medium;
    const now = Date.now() / 1000;
    this.store.delete(key);
    this.store.set(key, {
      value,
      cachedAt: now,
      expiresAt: now + ttlSeconds,
      ttlClass,
    });
    this.evictIfNeeded();
  }

  get(key: string): unknown | undefined {
    const entry = this.store.get(key);
    if (entry === undefined) {
      this.misses += 1;
      return undefined;
    }
    if (Date.now() / 1000 > entry.expiresAt) {
      this.store.delete(key);
      this.expirations += 1;
      this.misses += 1;
      return undefined;
    }
    // move to end (most recently used)
    this.store.delete(key);
    this.store.set(key, entry);
    this.hits += 1;
    return entry.value;
  }

  invalidate(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }

  stats(): CacheStats {
    this.purgeExpired();
    const requests = this.hits + this.misses;
    return {
      entries: this.store.size,
      maxsize: this.maxsize,
      hits: this.hits,
      misses: this.misses,
      evictions: this.evictions,
      expirations: this.expirations,
      hit_ratio: requests ? this.hits / requests : 0.0,
    };
  }
}
