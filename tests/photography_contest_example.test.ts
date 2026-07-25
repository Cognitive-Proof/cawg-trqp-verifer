import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadFeedDescriptor, validateFeedDescriptor } from "../src/feed_descriptor.js";
import { replayAuditBundle } from "../src/replay.js";

const EXAMPLE = "examples/photography_contest";

describe("photography contest example", () => {
  it("replays with signed feed descriptors", () => {
    const bundle = JSON.parse(readFileSync(`${EXAMPLE}/replay_bundle.json`, "utf-8"));
    const report = replayAuditBundle(bundle);
    expect(report.matches).toBe(true);
    expect(report.replayed_result.trust_outcome).toBe("trusted");
    expect((report.replayed_result.policy_evidence as any).feed_descriptors.policy.reason_code).toBe("fresh");
    expect((report.replayed_result.policy_evidence as any).feed_descriptors.revocation.reason_code).toBe("fresh");
  });

  it("keeps the decision receipt aligned with the replay bundle", () => {
    const receipt = JSON.parse(readFileSync(`${EXAMPLE}/decision_receipt.json`, "utf-8"));
    const bundle = JSON.parse(readFileSync(`${EXAMPLE}/replay_bundle.json`, "utf-8"));
    expect(receipt.decision.result).toBe(bundle.verification_result.trust_outcome);
    expect(receipt.evidence.replayable).toBe(true);
    expect(receipt.decision.reasons).toContain("feed_descriptors_valid");
  });

  it("validates feed descriptors against the demo trust anchor", () => {
    const trustAnchors = JSON.parse(readFileSync(`${EXAMPLE}/trust_anchors.json`, "utf-8"));
    const policyReport = validateFeedDescriptor(
      loadFeedDescriptor(`${EXAMPLE}/policy-feed.signed.json`),
      readFileSync(`${EXAMPLE}/contest_policy_feed.json`, "utf-8"),
      { trustAnchors, expectedAuthorities: new Set(["did:web:media-registry.example"]) },
    );
    const revocationReport = validateFeedDescriptor(
      loadFeedDescriptor(`${EXAMPLE}/revocation-feed.signed.json`),
      readFileSync(`${EXAMPLE}/contest_revocation_feed.json`, "utf-8"),
      { trustAnchors, expectedAuthorities: new Set(["did:web:media-registry.example"]) },
    );
    expect(policyReport.reason_code).toBe("fresh");
    expect(revocationReport.reason_code).toBe("fresh");
  });
});
