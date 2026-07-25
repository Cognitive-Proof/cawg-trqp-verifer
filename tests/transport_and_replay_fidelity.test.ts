import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { auditBundleToDict, buildAuditBundle } from "../src/audit.js";
import { createVerificationRequest, type VerificationRequest } from "../src/models.js";
import { MockTRQPService } from "../src/mock_service.js";
import { loadProfile } from "../src/profile.js";
import { replayAuditBundle } from "../src/replay.js";
import { Verifier } from "../src/verifier.js";

function request(): VerificationRequest {
  return createVerificationRequest(
    JSON.parse(readFileSync("examples/verification_request.json", "utf-8")) as VerificationRequest,
  );
}

describe("transport and replay fidelity", () => {
  it("rejects insufficient transport integrity for a strict overlay", () => {
    const profile = loadProfile({
      id: "strict_transport_test",
      base_profile: "standard",
      controls: {
        transport: { mode: "http", integrity: "signed", availability_requirement: "required" },
      },
      overlays: [],
      source: "inline",
    });
    const verifier = new Verifier({
      service: new MockTRQPService("data/policies.json", "data/revocations.json", { transportIntegrity: "tls" }),
    });
    const result = verifier.verify(request(), profile);
    expect(result.verification_mode).toBe("transport_guardrail");
    expect(result.policy_freshness).toBe("transport_violation");
    expect((result.policy_evidence.transport as any).satisfied).toBe(false);
  });

  it("keeps verification running on the revocation freshness warn path", () => {
    const profile = loadProfile({
      id: "warn_revocation_test",
      base_profile: "standard",
      controls: {
        transport: { mode: "http", integrity: "tls", availability_requirement: "best_effort" },
        revocation: { mode: "delta", hard_fail: false, max_age_seconds: 1, enforcement: "warn", delta_channel_required: false },
      },
      overlays: [],
      source: "inline",
    });
    const dir = mkdtempSync(path.join(tmpdir(), "trqp-stale-revocations-"));
    const stalePath = path.join(dir, "tmp_stale_revocations.json");
    writeFileSync(
      stalePath,
      JSON.stringify({
        revoked_entities: [],
        policy_epoch: "2026-Q1",
        issued_at: "2020-01-01T00:00:00Z",
        channel: "delta",
      }),
      "utf-8",
    );
    try {
      const verifier = new Verifier({ service: new MockTRQPService("data/policies.json", stalePath) });
      const result = verifier.verify(request(), profile);
      expect(result.trust_outcome).toBe("trusted");
      expect(result.policy_freshness).toBe("stale_but_warned");
      expect((result.policy_evidence.revocation_status as any).freshness_ok).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("carries the transport and revocation contract through replay", () => {
    const verifier = new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") });
    const result = verifier.verify(request(), "standard");
    const bundle = auditBundleToDict(
      buildAuditBundle(request(), result, {
        profile: "standard",
        exportedAt: "2026-03-31T00:00:00Z",
        policyPath: "data/policies.json",
        revocationPath: "data/revocations.json",
      }),
    );
    expect("transport_metadata" in (bundle.replay_inputs as any)).toBe(true);
    expect("revocation_status" in (bundle.replay_inputs as any)).toBe(true);
    expect((bundle.replay_inputs as any).replay_contract.revocation_freshness_evaluated).toBe(true);

    const report = replayAuditBundle(bundle);
    expect(report.matches).toBe(true);
  });

  it("keeps the canonical fixture manifest complete", () => {
    const manifest = JSON.parse(readFileSync("fixtures/profile-bound/standard-v1/manifest.json", "utf-8"));
    expect(manifest.fixture_id).toBe("standard-v1");
    expect(manifest.inputs.request).toBe("request.json");
    expect(existsSync("fixtures/profile-bound/standard-v1/pinned_feeds/policies.json")).toBe(true);
    expect(existsSync("fixtures/profile-bound/standard-v1/pinned_feeds/revocations.json")).toBe(true);
  });
});
