import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { createAjv } from "../src/ajv.js";
import { auditBundleToDict, buildAuditBundle } from "../src/audit.js";
import { HTTPTRQPService } from "../src/http_service.js";
import { createVerificationRequest, type VerificationRequest } from "../src/models.js";
import { MockTRQPService } from "../src/mock_service.js";
import { validateContext } from "../src/privacy.js";
import { Verifier } from "../src/verifier.js";

function loadRequest() {
  return createVerificationRequest(
    JSON.parse(readFileSync("examples/verification_request.json", "utf-8")) as VerificationRequest,
  );
}

async function result() {
  const request = loadRequest();
  const verifier = new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") });
  return { request, result: await verifier.verify(request) };
}

function schemaErrors(schemaPath: string, examplePath: string): unknown[] {
  const validate = createAjv().compile(JSON.parse(readFileSync(schemaPath, "utf-8")));
  const valid = validate(JSON.parse(readFileSync(examplePath, "utf-8")));
  return valid ? [] : (validate.errors ?? []);
}

describe("privacy controls", () => {
  it("validates all built-in privacy profiles against the schema", () => {
    const validate = createAjv().compile(JSON.parse(readFileSync("schemas/privacy-profile.schema.json", "utf-8")));
    for (const file of readdirSync("profiles/privacy")) {
      if (!file.endsWith(".json")) continue;
      const data = JSON.parse(readFileSync(path.join("profiles/privacy", file), "utf-8"));
      expect(validate(data) ? [] : validate.errors).toEqual([]);
    }
  });

  it("minimal_receipt redacts raw identifiers", async () => {
    const { request, result: res } = await result();
    const bundle = auditBundleToDict(buildAuditBundle(request, res, { privacyProfile: "minimal_receipt" }));
    const replayRequest = (bundle.replay_inputs as any).request;
    expect(replayRequest.entity_id).toBeUndefined();
    expect(replayRequest.entity_id_digest.startsWith("hmac-sha256:")).toBe(true);
    expect((bundle.replay_inputs as any).privacy.contains_raw_request).toBe(false);
  });

  it("replay_bundle retains the request for authorized replay", async () => {
    const { request, result: res } = await result();
    const bundle = auditBundleToDict(buildAuditBundle(request, res, { privacyProfile: "replay_bundle" }));
    expect((bundle.replay_inputs as any).request.entity_id).toBe(request.entity_id);
    expect((bundle.replay_inputs as any).privacy.access_scope).toBe("trqp.audit.export");
  });

  it("rejects unapproved context fields via an allow-list", () => {
    expect(() => validateContext({ territory: "US", email: "person@example.com" }, new Set(["territory"]))).toThrow();
  });

  it("validates retention/context/redaction examples against their schemas", () => {
    const pairs: [string, string][] = [
      ["schemas/retention-policy.schema.json", "examples/privacy/retention-policy.json"],
      ["schemas/context-profile.schema.json", "examples/privacy/context-profile.json"],
      ["schemas/redaction-policy.schema.json", "examples/privacy/redaction-policy.json"],
    ];
    for (const [schemaPath, examplePath] of pairs) {
      expect(schemaErrors(schemaPath, examplePath)).toEqual([]);
    }
  });

  it("requires the export scope for full replay bundles over HTTP", async () => {
    const service = new HTTPTRQPService(new MockTRQPService("data/policies.json", "data/revocations.json"));
    const server = service.app.listen(0);
    const port = (server.address() as { port: number }).port;
    try {
      const payload = { ...JSON.parse(readFileSync("examples/verification_request.json", "utf-8")), privacy_profile: "replay_bundle" };
      const denied = await fetch(`http://127.0.0.1:${port}/trqp/audit-bundle`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      expect(denied.status).toBe(403);

      const allowed = await fetch(`http://127.0.0.1:${port}/trqp/audit-bundle`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-TRQP-Scopes": "trqp.audit.export" },
        body: JSON.stringify(payload),
      });
      expect(allowed.status).toBe(200);
    } finally {
      server.close();
    }
  });
});
