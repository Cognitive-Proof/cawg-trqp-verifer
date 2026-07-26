import { describe, expect, it } from "vitest";
import { loadManifestFixture } from "../src/fixture_loader.js";
import { MockTRQPService } from "../src/mock_service.js";
import { SnapshotStore } from "../src/snapshot.js";
import { Verifier } from "../src/verifier.js";

describe("Verifier", () => {
  it("verifies a standard online request", async () => {
    const req = loadManifestFixture("examples/fixtures/cawg_manifest_minimal.json", "did:web:media-registry.example");
    const verifier = new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") });
    const result = await verifier.verify(req, "standard");
    expect(result.trust_outcome).toBe("trusted");
    expect(result.process_integrity).toBe("verified_high");
  });

  it("verifies an edge/offline snapshot request", async () => {
    const req = loadManifestFixture("examples/fixtures/cawg_manifest_minimal.json", "did:web:media-registry.example");
    const verifier = new Verifier({ snapshot: new SnapshotStore("data/snapshot.json", "data/trust_anchors.json") });
    const result = await verifier.verify(req, "edge");
    expect(result.trust_outcome).toBe("trusted_cached");
    expect(result.policy_freshness).toBe("snapshot_verified");
    expect(result.process_integrity).toBe("verified_high");
  });

  it("rejects a blocked/revoked entity", async () => {
    const req = loadManifestFixture("examples/fixtures/cawg_manifest_blocked.json", "did:web:media-registry.example");
    const verifier = new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") });
    const result = await verifier.verify(req, "standard");
    expect(result.trust_outcome).toBe("rejected");
    expect(result.actor_authorization).toBe("not_authorized");
  });

  it("rejects on failed process proof despite valid authorization", async () => {
    const req = loadManifestFixture(
      "examples/fixtures/cawg_manifest_c2pa_pop_failed.json",
      "did:web:media-registry.example",
    );
    const verifier = new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") });
    const result = await verifier.verify(req, "standard");
    expect(result.actor_authorization).toBe("authorized");
    expect(result.process_integrity).toBe("failed");
    expect(result.trust_outcome).toBe("rejected");
  });

  it("supports the real C2PA manifest fixture format", async () => {
    const req = loadManifestFixture("examples/fixtures/cawg_manifest_c2pa.json", "did:web:media-registry.example");
    const verifier = new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") });
    const result = await verifier.verify(req, "standard");
    expect(result.trust_outcome).toBe("trusted");
    expect(["verified", "verified_high"]).toContain(result.process_integrity);
  });

  it("applies a revocation delta to reject a previously-authorized entity", async () => {
    const req = loadManifestFixture("examples/fixtures/cawg_manifest_minimal.json", "did:web:media-registry.example");
    const verifier = new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") });
    await verifier.applyRevocationDelta([req.entity_id], "2026-Q2");
    const result = await verifier.verify(req, "standard");
    expect(result.trust_outcome).toBe("rejected");
    expect(result.policy_freshness).toBe("revoked");
    expect(result.explanations.some((e: string) => e.includes("revoked_in_epoch_2026-Q2"))).toBe(true);
  });
});
