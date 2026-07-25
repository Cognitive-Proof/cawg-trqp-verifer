import { describe, expect, it } from "vitest";
import { loadManifestFixture } from "../src/fixture_loader.js";
import { loadProfile, VerificationProfileError } from "../src/profile.js";
import { Verifier } from "../src/verifier.js";

describe("profile", () => {
  it("loads builtin profile with controls", () => {
    const profile = loadProfile("high_assurance");
    expect(profile.base_profile).toBe("high_assurance");
    expect(profile.controls.freshness.require_live).toBe(true);
    expect(profile.controls.evidence.require_attestation).toBe(true);
  });

  it("applies overlays to update profile controls", () => {
    const profile = loadProfile("standard", ["evidence_attested", "freshness_strict"]);
    expect(profile.controls.evidence.require_attestation).toBe(true);
    expect(profile.controls.freshness.require_live).toBe(true);
    expect(profile.controls.failure.network_failure).toBe("fail_closed");
    expect(profile.overlays).toEqual(["evidence_attested", "freshness_strict"]);
  });

  it("raises a validation error for an unknown profile", () => {
    expect(() => loadProfile("definitely-not-a-real-profile")).toThrow(VerificationProfileError);
  });

  it("fail-closed profile rejects service unavailable", () => {
    const request = loadManifestFixture(
      "examples/fixtures/cawg_manifest_minimal.json",
      "did:web:media-registry.example",
    );
    const verifier = new Verifier({ service: null });
    const result = verifier.verify(request, loadProfile("high_assurance"));
    expect(result.trust_outcome).toBe("rejected");
    expect(result.policy_freshness).toBe("service_unavailable");
  });

  it("fail-open profile defers on service unavailable", () => {
    const request = loadManifestFixture(
      "examples/fixtures/cawg_manifest_minimal.json",
      "did:web:media-registry.example",
    );
    const verifier = new Verifier({ service: null });
    const result = verifier.verify(request, loadProfile("standard"));
    expect(result.trust_outcome).toBe("deferred");
    expect(result.policy_freshness).toBe("service_unavailable");
  });
});
