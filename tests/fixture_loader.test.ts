import { describe, expect, it } from "vitest";
import { loadManifestFixture } from "../src/fixture_loader.js";
import { CAWGManifestParser } from "../src/manifest_parser.js";

describe("fixture loader", () => {
  it("loads a simplified fixture manifest", () => {
    const req = loadManifestFixture("examples/fixtures/cawg_manifest_minimal.json", "did:web:media-registry.example");
    expect(req.entity_id).toBe("did:web:publisher.example");
    expect(req.action).toBe("publish");
    expect(req.resource).toBe("cawg:news-content");
    expect(req.process_evidence).not.toBeNull();
  });

  it("loads a C2PA-style manifest", () => {
    const req = loadManifestFixture("examples/fixtures/cawg_manifest_c2pa.json", "did:web:media-registry.example");
    expect(req.entity_id).toBe("did:web:publisher.example");
    expect(req.context.credential_type).toBe("vc:creator-identity");
    expect(req.process_evidence).not.toBeNull();
  });

  it("reports the parser mode via the manifest validator", () => {
    const result = CAWGManifestParser.validateFixture("examples/fixtures/cawg_manifest_c2pa.json");
    expect(result.valid).toBe(true);
    expect(result.parser_mode).toBe("c2pa_json");
    expect(result.has_process_evidence).toBe(true);
  });
});
