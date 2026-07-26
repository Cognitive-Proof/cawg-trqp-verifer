import { beforeEach, describe, expect, it, vi } from "vitest";

const fakeClient = {
  get: vi.fn(async (_key: string): Promise<string | null> => null),
  set: vi.fn(async (..._args: unknown[]) => "OK"),
  del: vi.fn(async (_key: string) => 1),
};

vi.mock("../client.js", () => ({
  getRedisClient: vi.fn(() => fakeClient),
}));

const { RedisDecisionCache } = await import("../cache.js");

describe("RedisDecisionCache", () => {
  beforeEach(() => {
    fakeClient.get.mockClear();
    fakeClient.set.mockClear();
    fakeClient.del.mockClear();
    fakeClient.get.mockResolvedValue(null);
  });

  it("set() JSON-encodes the value and applies the ttlClass's TTL in seconds", async () => {
    const cache = new RedisDecisionCache();
    await cache.set("k", { authorized: true }, "short");

    expect(fakeClient.set).toHaveBeenCalledWith(
      "cawg-trqp:cache:k",
      JSON.stringify({ authorized: true }),
      "EX",
      300,
    );
  });

  it("set() defaults to the 'medium' ttlClass when none is given", async () => {
    const cache = new RedisDecisionCache();
    await cache.set("k", { authorized: true });

    expect(fakeClient.set).toHaveBeenCalledWith(
      "cawg-trqp:cache:k",
      JSON.stringify({ authorized: true }),
      "EX",
      3600,
    );
  });

  it("get() JSON-decodes a stored value", async () => {
    fakeClient.get.mockResolvedValueOnce(JSON.stringify({ authorized: true }));

    const cache = new RedisDecisionCache();
    const value = await cache.get("k");

    expect(fakeClient.get).toHaveBeenCalledWith("cawg-trqp:cache:k");
    expect(value).toEqual({ authorized: true });
  });

  it("get() returns undefined (not null) on a cache miss", async () => {
    const cache = new RedisDecisionCache();
    expect(await cache.get("missing")).toBeUndefined();
  });

  it("invalidate() deletes the namespaced key", async () => {
    const cache = new RedisDecisionCache();
    await cache.invalidate("k");

    expect(fakeClient.del).toHaveBeenCalledWith("cawg-trqp:cache:k");
  });

  it("honors a custom keyPrefix", async () => {
    const cache = new RedisDecisionCache({ keyPrefix: "myapp:" });
    await cache.invalidate("k");

    expect(fakeClient.del).toHaveBeenCalledWith("myapp:k");
  });
});
