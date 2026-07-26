# @cognitiveproof/cawg-trqp-plugin-redis

Redis-backed `DecisionCache` and `RevocationDeltaStore` for [`cawg-trqp-refimpl`](../../README.md), using [`ioredis`](https://github.com/redis/ioredis).

Use this when running more than one instance of the verifier/HTTP service: the core package's default in-memory `TTLCache` and `InMemoryRevocationDeltaStore` only affect the single process they're constructed in, so cache hits and pushed revocation deltas don't propagate across instances. Backing both by Redis makes them shared across every instance.

## Install

```bash
npm install @cognitiveproof/cawg-trqp-plugin-redis
```

## Usage

```ts
import { Verifier, MockTRQPService } from "cawg-trqp-refimpl";
import { RedisDecisionCache, RedisRevocationDeltaStore } from "@cognitiveproof/cawg-trqp-plugin-redis";

const verifier = new Verifier({
  service: new MockTRQPService("data/policies.json", "data/revocations.json"),
  cache: new RedisDecisionCache({ url: process.env.REDIS_URL }),
  revocationDeltaStore: new RedisRevocationDeltaStore({ url: process.env.REDIS_URL }),
});
```

Or with `HTTPTRQPService`:

```ts
import { HTTPTRQPService, MockTRQPService } from "cawg-trqp-refimpl";
import { RedisDecisionCache } from "@cognitiveproof/cawg-trqp-plugin-redis";

const service = new HTTPTRQPService(new MockTRQPService("data/policies.json", "data/revocations.json"), {
  cache: new RedisDecisionCache(),
});
```

## Configuration

Both classes accept an options object, or fall back to the `REDIS_URL` environment variable, or `redis://localhost:6379`:

```ts
new RedisDecisionCache({ url: "redis://my-redis:6379", keyPrefix: "myapp:cache:" });
new RedisRevocationDeltaStore({ url: "redis://my-redis:6379", key: "myapp:revocation-delta" });
```

Both share a single `ioredis` connection per process (see `src/client.ts`).
