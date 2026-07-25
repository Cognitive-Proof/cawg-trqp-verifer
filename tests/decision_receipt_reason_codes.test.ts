import { describe, expect, it } from "vitest";
import { FRESHNESS_REASON_CODES } from "../src/feed_descriptor.js";

describe("freshness reason codes", () => {
  it("are governance-stable", () => {
    const expected = [
      "fresh",
      "stale_but_warned",
      "stale_rejected",
      "missing_feed_descriptor",
      "descriptor_signature_invalid",
      "descriptor_digest_mismatch",
      "authority_not_recognized",
      "route_unattested",
      "revocation_channel_degraded",
    ];
    for (const code of expected) {
      expect(FRESHNESS_REASON_CODES.has(code)).toBe(true);
    }
  });
});
