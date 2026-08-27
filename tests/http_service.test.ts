import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { HTTPTRQPService } from "../src/http_service.js";
import { MockTRQPService } from "../src/mock_service.js";

describe("HTTP TRQP service endpoints", () => {
  let service: HTTPTRQPService;
  let server: ReturnType<HTTPTRQPService["app"]["listen"]>;
  let baseUrl: string;

  beforeEach(() => {
    service = new HTTPTRQPService(new MockTRQPService("data/policies.json", "data/revocations.json"));
    server = service.app.listen(0);
    const port = (server.address() as { port: number }).port;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterEach(() => {
    server.close();
  });

  it("responds to the health check", async () => {
    const response = await fetch(`${baseUrl}/health`);
    expect(response.status).toBe(200);
    const body = (await response.json()) as any;
    expect(body.status).toBe("healthy");
  });

  it("handles a valid authorization request", async () => {
    const payload = {
      entity_id: "did:web:publisher.example",
      authority_id: "did:web:media-registry.example",
      action: "publish",
      resource: "cawg:news-content",
      context: { jurisdiction: "IN" },
    };
    const response = await fetch(`${baseUrl}/authorization`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as any;
    expect("authorized" in body).toBe(true);
  });

  it("handles a valid recognition request", async () => {
    const payload = {
      entity_id: "did:web:creator.example",
      authority_id: "did:web:issuer.example",
      action: "publish",
      resource: "cawg:news-content",
      context: {},
    };
    const response = await fetch(`${baseUrl}/recognition`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as any;
    expect("recognized" in body).toBe(true);
  });

  it("handles a valid gateway authorization request", async () => {
    const payload = {
      entity_id: "did:web:publisher.example",
      authority_id: "did:web:media-registry.example",
      action: "publish",
      resource: "cawg:news-content",
      context: { jurisdiction: "IN" },
    };
    const response = await fetch(`${baseUrl}/trqp/gateway/authorization`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as any;
    expect("authorization" in body && "gateway_mediation" in body).toBe(true);
  });

  it("verifies via the gateway when requested", async () => {
    const payload = { ...JSON.parse(readFileSync("examples/verification_request.json", "utf-8")), use_gateway: true };
    const response = await fetch(`${baseUrl}/trqp/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as any;
    expect(body.verification_mode).toBe("gateway_mediated");
    expect(["trusted", "trusted_cached"]).toContain(body.trust_outcome);
  });

  it("exports an audit bundle", async () => {
    const payload = { ...JSON.parse(readFileSync("examples/verification_request.json", "utf-8")), use_gateway: true };
    const response = await fetch(`${baseUrl}/trqp/audit-bundle`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as any;
    expect(body.bundle_type).toBe("cawg-trqp-audit-bundle");
  });
});
