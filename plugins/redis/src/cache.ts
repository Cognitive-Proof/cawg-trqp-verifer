import type { DecisionCache } from "@cognitiveproof/cawg-trqp-plugin-types";
import type { Redis } from "ioredis";
import { getRedisClient } from "./client.js";

const TTL_SECONDS_BY_CLASS: Record<string, number> = {
  short: 300,
  medium: 3600,
  long: 86400,
};

export interface RedisDecisionCacheOptions {
  /** Redis connection string. Default: REDIS_URL env var, else redis://localhost:6379. */
  url?: string;
  /** Prefix for keys this cache writes, to avoid colliding with other Redis users. Default: "cawg-trqp:cache:". */
  keyPrefix?: string;
}

/**
 * Redis-backed DecisionCache<T> - a real drop-in replacement for the core
 * package's in-memory TTLCache, sharing cached authorization/recognition
 * decisions across every instance of a horizontally-scaled deployment.
 */
export class RedisDecisionCache<T = unknown> implements DecisionCache<T> {
  private readonly client: Redis;
  private readonly keyPrefix: string;

  constructor(options: RedisDecisionCacheOptions = {}) {
    this.client = getRedisClient(options.url);
    this.keyPrefix = options.keyPrefix ?? "cawg-trqp:cache:";
  }

  private namespacedKey(key: string): string {
    return `${this.keyPrefix}${key}`;
  }

  async set(key: string, value: T, ttlClass = "medium"): Promise<void> {
    const ttlSeconds = TTL_SECONDS_BY_CLASS[ttlClass] ?? TTL_SECONDS_BY_CLASS.medium;
    await this.client.set(this.namespacedKey(key), JSON.stringify(value), "EX", ttlSeconds);
  }

  async get(key: string): Promise<T | undefined> {
    const raw = await this.client.get(this.namespacedKey(key));
    if (raw === null) {
      return undefined;
    }
    return JSON.parse(raw) as T;
  }

  async invalidate(key: string): Promise<void> {
    await this.client.del(this.namespacedKey(key));
  }
}
