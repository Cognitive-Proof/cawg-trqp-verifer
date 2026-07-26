import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { signAuditBundleFromPath } from "../src/attestation.js";
import { auditBundleToDict, buildAuditBundle } from "../src/audit.js";
import { TrustGateway } from "../src/gateway.js";
import { createVerificationRequest, type VerificationRequest } from "../src/models.js";
import { MockTRQPService } from "../src/mock_service.js";
import { replayAuditBundle } from "../src/replay.js";
import { loadJson, validateAuditBundle } from "../src/validation.js";
import { Verifier } from "../src/verifier.js";

function loadRequest(path = "examples/verification_request.json") {
  return createVerificationRequest(JSON.parse(readFileSync(path, "utf-8")) as VerificationRequest);
}

describe("audit bundle", () => {
  it("contains policy and process data", async () => {
    const request = loadRequest();
    const verifier = new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") });
    const result = await verifier.verify(request);
    const bundle = auditBundleToDict(
      buildAuditBundle(request, result, {
        profile: "standard",
        policyPath: "data/policies.json",
        revocationPath: "data/revocations.json",
      }),
    );
    expect(bundle.bundle_type).toBe("cawg-trqp-audit-bundle");
    expect((bundle.verification_result as any).trust_outcome).toBe("trusted");
    expect((bundle.policy_evidence as any).authorization_evidence.length).toBeGreaterThan(0);
    expect((bundle.process_appraisal as any).status).toBe("verified");
    expect((bundle.replay_inputs as any).profile.id).toBe("standard");
    expect((bundle.replay_inputs as any).policy_feed.policy_source).toBe("data/policies.json");
    expect((bundle.bundle_digest_sha256 as string).length).toBe(64);
  });

  it("exports gateway mediation in the bundle", async () => {
    const request = loadRequest();
    const service = new MockTRQPService("data/policies.json");
    const verifier = new Verifier({ service, gateway: new TrustGateway(service, { gatewayId: "gateway:test" }) });
    const result = await verifier.verify(request);
    const bundle = auditBundleToDict(buildAuditBundle(request, result, { profile: "standard", useGateway: true }));
    expect((bundle.gateway_mediation as any).gateway_id).toBe("gateway:test");
    expect((bundle.replay_inputs as any).use_gateway).toBe(true);
  });

  it("passes schema and digest validation", async () => {
    const request = loadRequest();
    const verifier = new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") });
    const result = await verifier.verify(request);
    const bundle = auditBundleToDict(
      buildAuditBundle(request, result, {
        exportedAt: "2026-03-31T00:00:00Z",
        policyPath: "data/policies.json",
        revocationPath: "data/revocations.json",
      }),
    );
    const schema = loadJson("schemas/audit-bundle.schema.json");
    expect(validateAuditBundle(bundle, schema)).toEqual([]);
  });

  it("passes attestation validation once signed", async () => {
    const request = loadRequest();
    const verifier = new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") });
    const result = await verifier.verify(request);
    const bundle = auditBundleToDict(
      buildAuditBundle(request, result, {
        exportedAt: "2026-03-31T00:00:00Z",
        policyPath: "data/policies.json",
        revocationPath: "data/revocations.json",
      }),
    );
    const signedBundle = signAuditBundleFromPath(bundle, "data/snapshot_signing_key.example.pem", {
      keyId: "media-registry-snapshot-key-1",
    });
    const schema = loadJson("schemas/audit-bundle.schema.json");
    expect(validateAuditBundle(signedBundle, schema, { trustAnchorsPath: "data/trust_anchors.json" })).toEqual([]);
  });

  it("replays to match the original verification", async () => {
    const request = loadRequest();
    const verifier = new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") });
    const result = await verifier.verify(request);
    const bundle = auditBundleToDict(
      buildAuditBundle(request, result, {
        exportedAt: "2026-03-31T00:00:00Z",
        policyPath: "data/policies.json",
        revocationPath: "data/revocations.json",
      }),
    );
    const report = await replayAuditBundle(bundle);
    expect(report.matches).toBe(true);
    expect(report.differences).toEqual([]);
    expect(report.policy_sources.policy_source).toBe("data/policies.json");
  });
});
