import { Redis } from "ioredis";

// One shared connection per process, cached on globalThis - mirrors the
// pattern used by the other storage plugins in this monorepo (see the
// MongoDB plugin's client.ts) so repeated getRedisClient() calls (e.g. from
// both RedisDecisionCache and RedisRevocationDeltaStore) don't each open
// their own connection.
const globalForRedis = globalThis as unknown as { cawgTrqpRedisClient?: Redis };

export function getRedisClient(url?: string): Redis {
  if (!globalForRedis.cawgTrqpRedisClient) {
    const resolvedUrl = url ?? process.env.REDIS_URL ?? "redis://localhost:6379";
    globalForRedis.cawgTrqpRedisClient = new Redis(resolvedUrl);
  }
  return globalForRedis.cawgTrqpRedisClient;
}
