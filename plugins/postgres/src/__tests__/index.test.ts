import { beforeEach, describe, expect, it, vi } from "vitest";

let authorizationRows: unknown[] = [];
let recognitionRows: unknown[] = [];
let revocationRows: unknown[] = [];

const fakePool = {
  query: vi.fn(async (sql: string) => {
    if (sql.includes("FROM revocations")) return { rows: revocationRows };
    if (sql.includes("FROM authorizations")) return { rows: authorizationRows };
    if (sql.includes("FROM recognitions")) return { rows: recognitionRows };
    return { rows: [] };
  }),
};

vi.mock("../client.js", () => ({
  getPostgresPool: vi.fn(() => fakePool),
}));

const { PostgresPolicyService } = await import("../index.js");

describe("PostgresPolicyService", () => {
  beforeEach(() => {
    authorizationRows = [];
    recognitionRows = [];
    revocationRows = [];
    fakePool.query.mockClear();
  });

  it("authorization() rejects a revoked entity without querying the authorizations table", async () => {
    revocationRows = [{ revoked_entities: ["did:web:blocked.example"], policy_epoch: "2026-Q1" }];
    const service = new PostgresPolicyService();

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
    authorizationRows = [
      {
        entity_id: "did:web:publisher.example",
        authority_id: "did:web:media-registry.example",
        action: "publish",
        resource: "cawg:news-content",
        context: { jurisdiction: "IN" },
        authorized: true,
        policy_epoch: "2026-Q1",
        evidence: ["policy:1"],
        policy_requirements: {},
      },
    ];
    const service = new PostgresPolicyService();

    const result = await service.authorization(
      "did:web:publisher.example",
      "did:web:media-registry.example",
      "publish",
      "cawg:news-content",
      { jurisdiction: "IN", risk_tier: "medium" },
    );

    expect(result).toMatchObject({ authorized: true, policy_epoch: "2026-Q1", evidence: ["policy:1"] });
  });

  it("authorization() falls back to no_matching_policy when nothing matches", async () => {
    const service = new PostgresPolicyService();
    const result = await service.authorization("did:web:nobody.example", "did:web:x.example", "publish", "y", {});
    expect(result).toMatchObject({ authorized: false, reason: "no_matching_policy" });
  });

  it("recognition() matches by entity/authority/action/resource plus context subset", async () => {
    recognitionRows = [
      {
        entity_id: "did:web:creator.example",
        authority_id: "did:web:issuer.example",
        action: "publish",
        resource: "asset",
        context: {},
        recognized: true,
        policy_epoch: "2026-Q1",
      },
    ];
    const service = new PostgresPolicyService();

    const result = await service.recognition("did:web:creator.example", "did:web:issuer.example", "publish", "asset", {});

    expect(result).toMatchObject({ recognized: true, policy_epoch: "2026-Q1" });
  });
});
