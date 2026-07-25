import { loadManifestFixture } from "../src/fixture_loader.js";
import { MockTRQPService } from "../src/mock_service.js";
import { SnapshotStore } from "../src/snapshot.js";
import { Verifier } from "../src/verifier.js";

const authorityId = "did:web:media-registry.example";
const standardRequest = loadManifestFixture("examples/fixtures/cawg_manifest_minimal.json", authorityId);
const blockedRequest = loadManifestFixture("examples/fixtures/cawg_manifest_blocked.json", authorityId);

const standard = new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") });
const edge = new Verifier({ snapshot: new SnapshotStore("data/snapshot.json", null) });

console.log("=== Standard Profile: Allowed Entity ===");
console.log(JSON.stringify(standard.verify(standardRequest, "standard"), null, 2));

console.log("\n=== Edge Profile: Allowed Entity ===");
console.log(JSON.stringify(edge.verify(standardRequest, "edge"), null, 2));

console.log("\n=== Standard Profile: Blocked Entity ===");
console.log(JSON.stringify(standard.verify(blockedRequest, "standard"), null, 2));
