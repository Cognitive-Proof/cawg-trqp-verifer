import type { RevocationCheckResult, RevocationDeltaStore } from "@cognitiveproof/cawg-trqp-plugin-types";
import type { Redis } from "ioredis";
import { getRedisClient } from "./client.js";

export interface RedisRevocationDeltaStoreOptions {
  /** Redis connection string. Default: REDIS_URL env var, else redis://localhost:6379. */
  url?: string;
  /** Single Redis key holding the JSON-encoded delta state. Default: "cawg-trqp:revocation-delta". */
  key?: string;
}

interface StoredDeltaState {
  revokedEntities: string[];
  policyEpoch: string | null;
}

/**
 * Redis-backed RevocationDeltaStore - a real drop-in replacement for the core
 * package's InMemoryRevocationDeltaStore. Pushing a delta via set() is
 * visible to every instance of a horizontally-scaled deployment immediately,
 * rather than only the process that called it.
 */
export class RedisRevocationDeltaStore implements RevocationDeltaStore {
  private readonly client: Redis;
  private readonly key: string;

  constructor(options: RedisRevocationDeltaStoreOptions = {}) {
    this.client = getRedisClient(options.url);
    this.key = options.key ?? "cawg-trqp:revocation-delta";
  }

  async set(revokedEntities: string[], policyEpoch: string | null = null): Promise<void> {
    const state: StoredDeltaState = { revokedEntities, policyEpoch };
    await this.client.set(this.key, JSON.stringify(state));
  }

  async check(entityId: string): Promise<RevocationCheckResult> {
    const raw = await this.client.get(this.key);
    if (raw === null) {
      return { revoked: false, reason: null, policyEpoch: null };
    }
    const state = JSON.parse(raw) as StoredDeltaState;
    if (state.revokedEntities.includes(entityId)) {
      return {
        revoked: true,
        reason: `revoked_in_epoch_${state.policyEpoch ?? "unknown"}`,
        policyEpoch: state.policyEpoch,
      };
    }
    return { revoked: false, reason: null, policyEpoch: null };
  }
}
