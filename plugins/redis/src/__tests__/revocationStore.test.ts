import { beforeEach, describe, expect, it, vi } from "vitest";

const fakeClient = {
  get: vi.fn(async (_key: string): Promise<string | null> => null),
  set: vi.fn(async (..._args: unknown[]) => "OK"),
};

vi.mock("../client.js", () => ({
  getRedisClient: vi.fn(() => fakeClient),
}));

const { RedisRevocationDeltaStore } = await import("../revocationStore.js");

describe("RedisRevocationDeltaStore", () => {
  beforeEach(() => {
    fakeClient.get.mockClear();
    fakeClient.set.mockClear();
    fakeClient.get.mockResolvedValue(null);
  });

  it("check() reports not-revoked when no delta has ever been set", async () => {
    const store = new RedisRevocationDeltaStore();
    expect(await store.check("did:web:someone.example")).toEqual({
      revoked: false,
      reason: null,
      policyEpoch: null,
    });
  });

  it("set() JSON-encodes the revoked entities and epoch under a single key", async () => {
    const store = new RedisRevocationDeltaStore();
    await store.set(["did:web:blocked.example"], "2026-Q3");

    expect(fakeClient.set).toHaveBeenCalledWith(
      "cawg-trqp:revocation-delta",
      JSON.stringify({ revokedEntities: ["did:web:blocked.example"], policyEpoch: "2026-Q3" }),
    );
  });

  it("check() reports revoked with the epoch-qualified reason for a revoked entity", async () => {
    fakeClient.get.mockResolvedValueOnce(
      JSON.stringify({ revokedEntities: ["did:web:blocked.example"], policyEpoch: "2026-Q3" }),
    );

    const store = new RedisRevocationDeltaStore();
    expect(await store.check("did:web:blocked.example")).toEqual({
      revoked: true,
      reason: "revoked_in_epoch_2026-Q3",
      policyEpoch: "2026-Q3",
    });
  });

  it("check() reports not-revoked for an entity absent from the stored delta", async () => {
    fakeClient.get.mockResolvedValueOnce(
      JSON.stringify({ revokedEntities: ["did:web:blocked.example"], policyEpoch: "2026-Q3" }),
    );

    const store = new RedisRevocationDeltaStore();
    expect(await store.check("did:web:someone-else.example")).toEqual({
      revoked: false,
      reason: null,
      policyEpoch: null,
    });
  });

  it("honors a custom key", async () => {
    const store = new RedisRevocationDeltaStore({ key: "myapp:revocation" });
    await store.set([], null);

    expect(fakeClient.set).toHaveBeenCalledWith("myapp:revocation", expect.any(String));
  });
});
