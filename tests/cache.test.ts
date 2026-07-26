import { describe, expect, it } from "vitest";
import { TTLCache } from "../src/DecisionCache/index.js";

describe("TTLCache", () => {
  it("sets and gets values", async () => {
    const cache = new TTLCache();
    await cache.set("k", { x: 1 }, "medium");
    expect(await cache.get("k")).toEqual({ x: 1 });
  });

  it("evicts least recently used when maxsize reached", async () => {
    const cache = new TTLCache(2);
    await cache.set("a", 1);
    await cache.set("b", 2);
    expect(await cache.get("a")).toBe(1);
    await cache.set("c", 3);
    expect(await cache.get("a")).toBe(1);
    expect(await cache.get("b")).toBeUndefined();
    expect(await cache.get("c")).toBe(3);
  });

  it("tracks metrics and clears", async () => {
    const cache = new TTLCache(2);
    expect(await cache.get("missing")).toBeUndefined();
    await cache.set("a", 1);
    expect(await cache.get("a")).toBe(1);
    const stats = cache.stats();
    expect(stats.hits).toBe(1);
    expect(stats.misses).toBe(1);
    cache.clear();
    expect(cache.stats().entries).toBe(0);
  });
});
