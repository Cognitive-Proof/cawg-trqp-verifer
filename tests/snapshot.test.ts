import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { SnapshotStore } from "../src/snapshot.js";

describe("SnapshotStore", () => {
  it("looks up authorization entries and verifies the signature", () => {
    const store = new SnapshotStore("data/snapshot.json", "data/trust_anchors.json");
    const item = store.findAuthorization(
      "did:web:publisher.example",
      "did:web:media-registry.example",
      "publish",
      "cawg:news-content",
      { jurisdiction: "IN" },
    );
    expect(item).not.toBeNull();
    expect(item?.authorized).toBe(true);
    expect(store.signatureVerified).toBe(true);
  });

  it("detects a tampered snapshot", () => {
    const snapshot = JSON.parse(readFileSync("data/snapshot.json", "utf-8"));
    snapshot.authorization[0].authorized = false;
    const dir = mkdtempSync(path.join(tmpdir(), "trqp-snapshot-"));
    const tampered = path.join(dir, "snapshot.json");
    writeFileSync(tampered, JSON.stringify(snapshot), "utf-8");

    const store = new SnapshotStore(tampered, "data/trust_anchors.json");
    expect(store.isUsable()).toBe(false);
    expect(store.validationErrors).toContain("invalid_snapshot_signature");
  });

  it("enforces snapshot expiry", () => {
    const store = new SnapshotStore("data/snapshot.json", "data/trust_anchors.json", {
      currentTime: new Date("2027-01-01T00:00:00Z"),
    });
    expect(store.isUsable()).toBe(false);
    expect(store.validationErrors).toContain("expired_snapshot");
  });
});
