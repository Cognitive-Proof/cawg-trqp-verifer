import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { validateFeedDescriptor } from "../src/feed_descriptor.js";

const TRUST = JSON.parse(readFileSync("data/trust_anchors.json", "utf-8"));
const BODY = readFileSync("data/policies.json", "utf-8");

function policyDescriptor(): Record<string, any> {
  return JSON.parse(readFileSync("examples/feed_descriptors/policy-feed.signed.json", "utf-8"));
}

describe("feed descriptor negative conformance vectors", () => {
  it("flags an authority that is not in the expected set", () => {
    const descriptor = policyDescriptor();
    const report = validateFeedDescriptor(descriptor, BODY, {
      trustAnchors: TRUST,
      expectedAuthorities: new Set(["did:web:another-registry.example"]),
    });
    expect(report.reason_code).toBe("authority_not_recognized");
  });

  it("flags an unattested gateway route when required", () => {
    const descriptor = policyDescriptor();
    descriptor.route.attested = false;
    const report = validateFeedDescriptor(descriptor, BODY, {
      trustAnchors: TRUST,
      expectedAuthorities: new Set(["did:web:media-registry.example"]),
      routeRequired: true,
    });
    expect(["descriptor_signature_invalid", "route_unattested"]).toContain(report.reason_code);
  });
});
