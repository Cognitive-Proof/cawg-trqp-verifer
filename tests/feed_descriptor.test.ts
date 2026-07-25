import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { validateFeedDescriptor } from "../src/feed_descriptor.js";
import { loadManifestFixture } from "../src/fixture_loader.js";
import { MockTRQPService } from "../src/mock_service.js";
import { Verifier } from "../src/verifier.js";

const TRUST = JSON.parse(readFileSync("data/trust_anchors.json", "utf-8"));

function descriptor(name: string): Record<string, any> {
  return JSON.parse(readFileSync(`examples/feed_descriptors/${name}.signed.json`, "utf-8"));
}

describe("feed descriptor validation", () => {
  it("passes signature, digest, and authority checks", () => {
    const desc = descriptor("policy-feed");
    const body = readFileSync(desc.feed.source, "utf-8");
    const report = validateFeedDescriptor(desc, body, {
      trustAnchors: TRUST,
      expectedAuthorities: new Set(["did:web:media-registry.example"]),
    });
    expect(report.reason_code).toBe("fresh");
    expect(report.signature_ok).toBe(true);
    expect(report.integrity_ok).toBe(true);
    expect(report.authority_ok).toBe(true);
  });

  it("detects a digest mismatch", () => {
    const desc = descriptor("policy-feed");
    const report = validateFeedDescriptor(desc, '{"tampered":true}', {
      trustAnchors: TRUST,
      expectedAuthorities: new Set(["did:web:media-registry.example"]),
    });
    expect(report.reason_code).toBe("descriptor_digest_mismatch");
    expect(report.integrity_ok).toBe(false);
  });

  it("detects a signature mismatch when descriptor content is altered", () => {
    const desc = descriptor("policy-feed");
    desc.feed.source = "data/other.json";
    const body = readFileSync("data/policies.json", "utf-8");
    const report = validateFeedDescriptor(desc, body, {
      trustAnchors: TRUST,
      expectedAuthorities: new Set(["did:web:media-registry.example"]),
    });
    expect(report.reason_code).toBe("descriptor_signature_invalid");
  });

  it("exports feed descriptor evidence from a live verification", () => {
    const req = loadManifestFixture("examples/fixtures/cawg_manifest_minimal.json", "did:web:media-registry.example");
    const verifier = new Verifier({
      service: new MockTRQPService("data/policies.json", "data/revocations.json", {
        policyDescriptorPath: "examples/feed_descriptors/policy-feed.signed.json",
        revocationDescriptorPath: "examples/feed_descriptors/revocation-feed.signed.json",
      }),
    });
    const result = verifier.verify(req, "standard");
    expect(result.trust_outcome).toBe("trusted");
    expect(result.policy_freshness).toBe("fresh");
    const feedDescriptors = result.policy_evidence.feed_descriptors as Record<string, any>;
    expect(feedDescriptors.policy.reason_code).toBe("fresh");
  });
});
