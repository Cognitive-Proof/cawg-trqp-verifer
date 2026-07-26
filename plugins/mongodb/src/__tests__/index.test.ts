import { beforeEach, describe, expect, it, vi } from "vitest";

const authorizationDocs: unknown[] = [];
const recognitionDocs: unknown[] = [];
let revocationDoc: unknown = null;

const collections: Record<string, { findOne: ReturnType<typeof vi.fn>; find: ReturnType<typeof vi.fn> }> = {
  authorizations: {
    findOne: vi.fn(),
    find: vi.fn(() => ({ toArray: async () => authorizationDocs })),
  },
  recognitions: {
    findOne: vi.fn(),
    find: vi.fn(() => ({ toArray: async () => recognitionDocs })),
  },
  revocations: {
    findOne: vi.fn(async () => revocationDoc),
    find: vi.fn(),
  },
};

vi.mock("../client.js", () => ({
  getCollection: vi.fn(async (name: string) => collections[name]),
}));

const { MongoPolicyService } = await import("../index.js");

describe("MongoPolicyService", () => {
  beforeEach(() => {
    authorizationDocs.length = 0;
    recognitionDocs.length = 0;
    revocationDoc = null;
  });

  it("authorization() rejects a revoked entity without consulting the authorizations collection", async () => {
    revocationDoc = { revoked_entities: ["did:web:blocked.example"], policy_epoch: "2026-Q1" };
    const service = new MongoPolicyService();

    const result = await service.authorization(
      "did:web:blocked.example",
      "did:web:media-registry.example",
      "publish",
      "cawg:news-content",
      {},
    );

    expect(result).toMatchObject({ authorized: false, reason: "entity_revoked", policy_epoch: "2026-Q1" });
  });

  it("authorization() matches on entity/authority/action/resource plus a context subset", async () => {
    authorizationDocs.push({
      entity_id: "did:web:publisher.example",
      authority_id: "did:web:media-registry.example",
      action: "publish",
      resource: "cawg:news-content",
      context: { jurisdiction: "IN" },
      authorized: true,
      policy_epoch: "2026-Q1",
      evidence: ["policy:1"],
    });
    const service = new MongoPolicyService();

    const result = await service.authorization(
      "did:web:publisher.example",
      "did:web:media-registry.example",
      "publish",
      "cawg:news-content",
      { jurisdiction: "IN", risk_tier: "medium" }, // extra request-side key is fine (subset match)
    );

    expect(result).toMatchObject({ authorized: true, policy_epoch: "2026-Q1", evidence: ["policy:1"] });
  });

  it("authorization() falls back to no_matching_policy when nothing matches", async () => {
    const service = new MongoPolicyService();
    const result = await service.authorization("did:web:nobody.example", "did:web:x.example", "publish", "y", {});
    expect(result).toMatchObject({ authorized: false, reason: "no_matching_policy" });
  });

  it("recognition() matches by authority/recognized-authority plus context subset", async () => {
    recognitionDocs.push({
      authority_id: "did:web:media-registry.example",
      recognized_authority_id: "did:web:issuer.example",
      context: {},
      recognized: true,
      policy_epoch: "2026-Q1",
    });
    const service = new MongoPolicyService();

    const result = await service.recognition(
      "did:web:media-registry.example",
      "did:web:issuer.example",
      {},
    );

    expect(result).toMatchObject({ recognized: true, policy_epoch: "2026-Q1" });
  });

  it("revocationStatus() reports age_seconds computed from issued_at", async () => {
    revocationDoc = { issued_at: new Date(Date.now() - 5000).toISOString(), policy_epoch: "2026-Q1", channel: "delta" };
    const service = new MongoPolicyService();

    const status = await service.revocationStatus();

    expect(status.policy_epoch).toBe("2026-Q1");
    expect(status.channel).toBe("delta");
    expect(status.age_seconds).toBeGreaterThanOrEqual(4);
  });
});
