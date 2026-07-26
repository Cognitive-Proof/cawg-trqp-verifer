import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { TTLCache } from "../src/cache.js";
import { TrustGateway } from "../src/gateway.js";
import { CAWGManifestParser } from "../src/manifest_parser.js";
import { createVerificationRequest, type VerificationRequest, verificationResultToDict } from "../src/models.js";
import { MockTRQPService } from "../src/mock_service.js";
import { SnapshotStore } from "../src/snapshot.js";
import { Verifier } from "../src/verifier.js";

function loadRequestData(path = "examples/verification_request.json"): VerificationRequest {
  return JSON.parse(readFileSync(path, "utf-8")) as VerificationRequest;
}

describe("standard profile conformance", () => {
  it("authorizes a standard trusted entity", async () => {
    const data = loadRequestData();
    const verifier = new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") });
    const result = verificationResultToDict(await verifier.verify(createVerificationRequest(data), "standard"));
    expect(result.trust_outcome).toBe("trusted");
    expect(result.process_integrity).toBe("verified_high");
    expect((result.policy_evidence as any).authorization_evidence.length).toBeGreaterThan(0);
  });

  it("reuses the cache on a second lookup", async () => {
    const data = loadRequestData();
    const cache = new TTLCache();
    const service = new MockTRQPService("data/policies.json", "data/revocations.json", {
      policyDescriptorPath: "examples/feed_descriptors/policy-feed.signed.json",
      revocationDescriptorPath: "examples/feed_descriptors/revocation-feed.signed.json",
    });
    const verifier = new Verifier({ service, cache });

    const result1 = await verifier.verify(createVerificationRequest(data), "standard");
    expect(result1.explanations).toContain("Live authorization lookup executed");

    const result2 = await verifier.verify(createVerificationRequest(data), "standard");
    expect(result2.explanations).toContain("Authorization cache hit");
    expect(result1.trust_outcome).toBe(result2.trust_outcome);
  });

  it("rejects when the missing process proof is required", async () => {
    const data = { ...loadRequestData(), process_evidence: null };
    const verifier = new Verifier({ service: new MockTRQPService("data/policies.json") });
    const result = await verifier.verify(createVerificationRequest(data), "standard");
    expect(result.actor_authorization).toBe("authorized");
    expect(result.process_integrity).toBe("missing_required_proof");
    expect(result.trust_outcome).toBe("rejected");
  });
});

describe("edge profile conformance", () => {
  it("authorizes from a verified snapshot", async () => {
    const data = loadRequestData();
    const verifier = new Verifier({ snapshot: new SnapshotStore("data/snapshot.json", "data/trust_anchors.json") });
    const result = verificationResultToDict(await verifier.verify(createVerificationRequest(data), "edge"));
    expect(result.trust_outcome).toBe("trusted_cached");
    expect(result.policy_freshness).toBe("snapshot_verified");
  });
});

describe("high assurance profile conformance", () => {
  it("always performs a live lookup", async () => {
    const data = loadRequestData();
    const cache = new TTLCache();
    const service = new MockTRQPService("data/policies.json", "data/revocations.json", {
      policyDescriptorPath: "examples/feed_descriptors/policy-feed.signed.json",
      revocationDescriptorPath: "examples/feed_descriptors/revocation-feed.signed.json",
    });
    const verifier = new Verifier({ service, cache });
    await verifier.verify(createVerificationRequest(data), "standard");
    expect(cache.cache.size).toBeGreaterThan(0);

    const verifier2 = new Verifier({ service, cache });
    const result = await verifier2.verify(createVerificationRequest(data), "high_assurance");
    expect(result.verification_mode).toBe("online_full");
  });
});

describe("gateway vectors", () => {
  it("verifies a gateway-mediated interoperability vector", async () => {
    const data: Record<string, unknown> = JSON.parse(readFileSync("examples/interoperability_vector_gateway.json", "utf-8"));
    delete data.use_gateway;
    delete data.profile;
    const service = new MockTRQPService("data/policies.json");
    const verifier = new Verifier({ service, gateway: new TrustGateway(service, { gatewayId: "gateway:interop" }) });
    const result = await verifier.verify(createVerificationRequest(data as unknown as VerificationRequest), "standard");
    expect(result.verification_mode).toBe("gateway_mediated");
    expect((result.gateway_mediation as any).gateway_id).toBe("gateway:interop");
  });

  it("verifies the benchmark fixtures", async () => {
    const service = new MockTRQPService("data/policies.json");
    const verifier = new Verifier({ service });
    for (const path of ["examples/benchmark_high_volume_request.json", "examples/benchmark_constrained_device_request.json"]) {
      const data = JSON.parse(readFileSync(path, "utf-8"));
      const result = await verifier.verify(createVerificationRequest(data));
      expect(result.trust_outcome).toBe("trusted");
    }
  });
});

describe("manifest parser conformance", () => {
  it("extracts signals from a C2PA JSON manifest", () => {
    const signal = CAWGManifestParser.parseFile("examples/fixtures/cawg_manifest_c2pa.json");
    expect(signal.parser_mode).toBe("c2pa_json");
    expect(signal.actor_id).toBe("did:web:publisher.example");
    expect(signal.issuer_id).toBe("did:web:issuer.example");
    expect(signal.action).toBe("publish");
    expect(signal.resource).toBe("cawg:news-content");
    expect(signal.context.credential_type).toBe("vc:creator-identity");
    expect(signal.process_evidence).not.toBeNull();
  });
});

describe("negative conformance vectors", () => {
  it("rejects a gateway-required profile over plain HTTP transport", async () => {
    const data = loadRequestData();
    const service = new MockTRQPService("data/policies.json", "data/revocations.json", { transportMode: "http" });
    const verifier = new Verifier({ service });
    const profile = {
      id: "gateway_required_negative",
      base_profile: "standard",
      controls: {
        transport: { mode: "gateway", integrity: "tls", availability_requirement: "required" },
      },
      overlays: [],
      source: "inline",
    };
    const result = await verifier.verify(createVerificationRequest(data), profile);
    expect(["rejected", "deferred"]).toContain(result.trust_outcome);
    expect(result.policy_freshness).toBe("transport_violation");
    expect((result.policy_evidence.transport as any).satisfied).toBe(false);
  });

  it("rejects on a stale revocation feed when enforcement is 'fail'", async () => {
    const data = loadRequestData();
    const service = new MockTRQPService("data/policies.json", "data/revocations.json");
    service.revocations.issued_at = "2020-01-01T00:00:00Z";
    const verifier = new Verifier({ service });
    const profile = {
      id: "stale_revocation_fail_negative",
      base_profile: "standard",
      controls: {
        revocation: { max_age_seconds: 1, enforcement: "fail", delta_channel_required: true },
        failure: { network_failure: "fail_closed", policy_unavailable: "fail_closed" },
        transport: { mode: "http", integrity: "tls", availability_requirement: "best_effort" },
      },
      overlays: [],
      source: "inline",
    };
    const result = await verifier.verify(createVerificationRequest(data), profile);
    expect(result.trust_outcome).toBe("rejected");
    expect(result.policy_freshness).toBe("revocation_stale");
    expect((result.policy_evidence.revocation_status as any).freshness_ok).toBe(false);
  });

  it("defers/continues with a warning on a stale revocation feed when enforcement is 'warn'", async () => {
    const data = loadRequestData();
    const service = new MockTRQPService("data/policies.json", "data/revocations.json");
    service.revocations.issued_at = "2020-01-01T00:00:00Z";
    const verifier = new Verifier({ service });
    const profile = {
      id: "stale_revocation_warn_negative",
      base_profile: "standard",
      controls: {
        revocation: { max_age_seconds: 1, enforcement: "warn", delta_channel_required: true },
        transport: { mode: "http", integrity: "tls", availability_requirement: "best_effort" },
      },
      overlays: [],
      source: "inline",
    };
    const result = await verifier.verify(createVerificationRequest(data), profile);
    expect(result.policy_freshness).toBe("stale_but_warned");
    expect((result.policy_evidence.revocation_status as any).freshness_ok).toBe(false);
    expect(result.trust_outcome).toBe("trusted");
  });
});
