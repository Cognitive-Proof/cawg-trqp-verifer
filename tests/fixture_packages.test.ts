import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { TrustGateway } from "../src/gateway.js";
import { createVerificationRequest, verificationResultToDict, type VerificationRequest } from "../src/models.js";
import { MockTRQPService } from "../src/mock_service.js";
import { Verifier } from "../src/verifier.js";

const FIXTURE_ROOT = "fixtures/profile-bound";

const cases: [string, () => Verifier, string][] = [
  ["standard-v1", () => new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") }), "standard"],
  [
    "high-assurance-v1",
    () =>
      new Verifier({
        service: new MockTRQPService("data/policies.json", "data/revocations.json", {
          policyDescriptorPath: "examples/feed_descriptors/policy-feed.signed.json",
          revocationDescriptorPath: "examples/feed_descriptors/revocation-feed.signed.json",
        }),
      }),
    "high_assurance",
  ],
  [
    "gateway-standard-v1",
    () => {
      const service = new MockTRQPService("data/policies.json", "data/revocations.json");
      return new Verifier({
        service,
        gateway: new TrustGateway(new MockTRQPService("data/policies.json", "data/revocations.json"), {
          gatewayId: "gateway:interop",
          routeLabel: "route:gateway-standard",
        }),
      });
    },
    "standard",
  ],
  [
    "multi-authority-v1",
    () =>
      new Verifier({
        gateway: new TrustGateway(null, {
          gatewayId: "gateway:mesh",
          authorityRoutes: {
            "did:web:media-registry.example": {
              service: new MockTRQPService("data/policies_multi_authority.json", "data/revocations.json"),
              route_label: "route:media-india",
            },
            "did:web:coalition-registry.example": {
              service: new MockTRQPService("data/policies_multi_authority.json", "data/revocations.json"),
              route_label: "route:coalition-eu",
            },
          },
        }),
      }),
    "standard",
  ],
];

describe("fixture packages replay to expected outcomes", () => {
  it.each(cases)("%s", async (fixtureName, verifierFactory, profile) => {
    const base = path.join(FIXTURE_ROOT, fixtureName);
    const request = createVerificationRequest(
      JSON.parse(readFileSync(path.join(base, "request.json"), "utf-8")) as VerificationRequest,
    );
    const expected = JSON.parse(readFileSync(path.join(base, "expected_result.json"), "utf-8"));
    const result = verificationResultToDict(await verifierFactory().verify(request, profile));

    expect(result.trust_outcome).toBe(expected.trust_outcome);
    expect(result.verification_mode).toBe(expected.verification_mode);
    expect((result.policy_evidence as any).verification_profile.id).toBe(
      expected.policy_evidence.verification_profile.id,
    );
  });
});
