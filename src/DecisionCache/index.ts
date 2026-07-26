const TTL_BY_CLASS: Record<string, number> = {
  short: 300,
  medium: 3600,
  long: 86400,
};

/**
 * Contract for anything that can cache verifier decisions. Async because a
 * real implementation (Redis, Memcached, some other shared store) has to do
 * network I/O; TTLCache below is a purely in-memory adapter whose methods
 * happen to resolve instantly, but callers must always await them so a
 * distributed implementation is a true drop-in replacement.
 */
export interface DecisionCache<T = unknown> {
  set(key: string, value: T, ttlClass?: string): Promise<void>;
  get(key: string): Promise<T | undefined>;
  invalidate(key: string): Promise<void>;
}

interface CacheEntry<T> {
  value: T;
  cachedAt: number;
  expiresAt: number;
  ttlClass: string;
}

/** Explicit cache-disabled adapter for live-only deployments and tests. */
export class NoOpDecisionCache<T = unknown> implements DecisionCache<T> {
  async set(_key: string, _value: T, _ttlClass = "medium"): Promise<void> {
    return undefined;
  }

  async get(_key: string): Promise<undefined> {
    return undefined;
  }

  async invalidate(_key: string): Promise<void> {
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
 * adapter - in-process only (see NOTE on statelessness across instances).
 * Production deployments spanning multiple instances should replace it with
 * a shared implementation of DecisionCache (Redis, etc.); Verifier and
 * HTTPTRQPService only depend on the DecisionCache interface, so any such
 * implementation is a drop-in replacement. Node is single-threaded, so unlike
 * the Python TTLCache this needs no lock.
 */
export class TTLCache<T = unknown> implements DecisionCache<T> {
  readonly maxsize: number;
  private store: Map<string, CacheEntry<T>> = new Map();
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

  get cache(): Map<string, CacheEntry<T>> {
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

  async set(key: string, value: T, ttlClass = "medium"): Promise<void> {
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

  async get(key: string): Promise<T | undefined> {
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

  async invalidate(key: string): Promise<void> {
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
