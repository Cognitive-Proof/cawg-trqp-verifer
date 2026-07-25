import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { auditBundleToDict, buildAuditBundle } from "../src/audit.js";
import { createVerificationRequest, type VerificationRequest } from "../src/models.js";
import { MockTRQPService } from "../src/mock_service.js";
import { Verifier } from "../src/verifier.js";

describe("audit bundle feed descriptor evidence", () => {
  it("carries feed descriptor evidence into replay inputs", () => {
    const request = createVerificationRequest(
      JSON.parse(readFileSync("examples/verification_request.json", "utf-8")) as VerificationRequest,
    );
    const verifier = new Verifier({
      service: new MockTRQPService("data/policies.json", "data/revocations.json", {
        policyDescriptorPath: "examples/feed_descriptors/policy-feed.signed.json",
        revocationDescriptorPath: "examples/feed_descriptors/revocation-feed.signed.json",
      }),
    });
    const result = verifier.verify(request);
    const bundle = auditBundleToDict(
      buildAuditBundle(request, result, { policyPath: "data/policies.json", revocationPath: "data/revocations.json" }),
    );
    expect((bundle.policy_evidence as any).feed_descriptors.policy.reason_code).toBe("fresh");
    expect((bundle.replay_inputs as any).feed_descriptors.revocation.reason_code).toBe("fresh");
  });
});
