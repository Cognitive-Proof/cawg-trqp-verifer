import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { auditBundleToDict, buildAuditBundle } from "../src/audit.js";
import { validateFeedDescriptor } from "../src/feed_descriptor.js";
import { HTTPTRQPService } from "../src/http_service.js";
import { createVerificationRequest, type VerificationRequest } from "../src/models.js";
import { MockTRQPService } from "../src/mock_service.js";
import { replayAuditBundle } from "../src/replay.js";
import { Verifier } from "../src/verifier.js";

function request(): VerificationRequest {
  return createVerificationRequest(
    JSON.parse(readFileSync("examples/verification_request.json", "utf-8")) as VerificationRequest,
  );
}

describe("HTTP security hardening", () => {
  let service: HTTPTRQPService;
  let server: ReturnType<HTTPTRQPService["app"]["listen"]>;
  let baseUrl: string;

  beforeEach(() => {
    service = new HTTPTRQPService("data/policies.json", "data/revocations.json");
    server = service.app.listen(0);
    const port = (server.address() as { port: number }).port;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterEach(() => {
    server.close();
  });

  it("rejects a filesystem path passed as the profile", async () => {
    const payload = { ...JSON.parse(readFileSync("examples/verification_request.json", "utf-8")), profile: "profiles/high_assurance.json" };
    const response = await fetch(`${baseUrl}/trqp/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    expect(response.status).toBe(400);
    expect(((await response.json()) as any).error).toBe("invalid_request");
  });

  it("rejects a non-JSON request body", async () => {
    const response = await fetch(`${baseUrl}/trqp/authorization`, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: "not-json",
    });
    expect(response.status).toBe(415);
    expect(((await response.json()) as any).error).toBe("invalid_request");
  });
});

describe("high assurance transport guardrails", () => {
  it("fails closed without feed descriptors", () => {
    const verifier = new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") });
    const result = verifier.verify(request(), "high_assurance");
    expect(result.verification_mode).toBe("transport_guardrail");
    expect(result.trust_outcome).toBe("rejected");
    expect(result.explanations[0]).toContain("missing_feed_descriptor");
  });

  it("accepts valid feed descriptors", () => {
    const verifier = new Verifier({
      service: new MockTRQPService("data/policies.json", "data/revocations.json", {
        policyDescriptorPath: "examples/feed_descriptors/policy-feed.signed.json",
        revocationDescriptorPath: "examples/feed_descriptors/revocation-feed.signed.json",
      }),
    });
    const result = verifier.verify(request(), "high_assurance");
    expect(result.trust_outcome).toBe("trusted");
    expect((result.policy_evidence.feed_descriptors as any).policy.reason_code).toBe("fresh");
    expect((result.policy_evidence.feed_descriptors as any).revocation.reason_code).toBe("fresh");
  });
});

describe("feed descriptor hardening", () => {
  it("produces a stable reason code for a malformed timestamp", () => {
    const descriptor = JSON.parse(readFileSync("examples/feed_descriptors/policy-feed.signed.json", "utf-8"));
    descriptor.valid_until = "not-a-timestamp";
    const report = validateFeedDescriptor(descriptor, readFileSync("data/policies.json", "utf-8"), {
      trustAnchors: JSON.parse(readFileSync("data/trust_anchors.json", "utf-8")),
      expectedAuthorities: new Set(["did:web:media-registry.example"]),
    });
    expect(report.reason_code).toBe("descriptor_malformed");
    expect(report.freshness_ok).toBe(false);
  });
});

describe("replay path hardening", () => {
  it("rejects a bundle policy path outside the trusted root", () => {
    const verifier = new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") });
    const result = verifier.verify(request(), "standard");
    const bundle = auditBundleToDict(
      buildAuditBundle(request(), result, {
        profile: "standard",
        policyPath: "data/policies.json",
        revocationPath: "data/revocations.json",
      }),
    );
    (bundle.replay_inputs as any).policy_feed.policy_source = "/tmp/outside-policy.json";
    expect(() => replayAuditBundle(bundle)).toThrow(/trusted replay root/);
  });

  it("rejects a bundle with a policy digest mismatch", () => {
    const verifier = new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") });
    const result = verifier.verify(request(), "standard");
    const bundle = auditBundleToDict(
      buildAuditBundle(request(), result, {
        profile: "standard",
        policyPath: "data/policies.json",
        revocationPath: "data/revocations.json",
      }),
    );
    (bundle.replay_inputs as any).policy_feed.policy_source_sha256 = "0".repeat(64);
    expect(() => replayAuditBundle(bundle)).toThrow(/digest mismatch/);
  });
});
