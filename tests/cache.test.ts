import { describe, expect, it } from "vitest";
import { TTLCache } from "../src/cache.js";

describe("TTLCache", () => {
  it("sets and gets values", () => {
    const cache = new TTLCache();
    cache.set("k", { x: 1 }, "medium");
    expect(cache.get("k")).toEqual({ x: 1 });
  });

  it("evicts least recently used when maxsize reached", () => {
    const cache = new TTLCache(2);
    cache.set("a", 1);
    cache.set("b", 2);
    expect(cache.get("a")).toBe(1);
    cache.set("c", 3);
    expect(cache.get("a")).toBe(1);
    expect(cache.get("b")).toBeUndefined();
    expect(cache.get("c")).toBe(3);
  });

  it("tracks metrics and clears", () => {
    const cache = new TTLCache(2);
    expect(cache.get("missing")).toBeUndefined();
    cache.set("a", 1);
    expect(cache.get("a")).toBe(1);
    const stats = cache.stats();
    expect(stats.hits).toBe(1);
    expect(stats.misses).toBe(1);
    cache.clear();
    expect(cache.stats().entries).toBe(0);
  });
});
