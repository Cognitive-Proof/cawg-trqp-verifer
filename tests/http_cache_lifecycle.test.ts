import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { HTTPTRQPService } from "../src/http_service.js";
import { MockTRQPService } from "../src/mock_service.js";

async function withServer<T>(service: HTTPTRQPService, fn: (baseUrl: string) => Promise<T>): Promise<T> {
  const server = service.app.listen(0);
  const port = (server.address() as { port: number }).port;
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    server.close();
  }
}

describe("HTTP cache lifecycle", () => {
  it("reuses the cache across requests", async () => {
    const service = new HTTPTRQPService(new MockTRQPService("data/policies.json", "data/revocations.json"));
    const payload = readFileSync("examples/verification_request.json", "utf-8");
    await withServer(service, async (baseUrl) => {
      const first = await fetch(`${baseUrl}/trqp/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload,
      });
      const second = await fetch(`${baseUrl}/trqp/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload,
      });
      expect(first.status).toBe(200);
      expect(second.status).toBe(200);
      expect(service.cache.stats().hits).toBeGreaterThanOrEqual(1);
      const secondBody = (await second.json()) as any;
      expect(secondBody.explanations).toContain("Authorization cache hit");
    });
  });

  it("shares the L1 cache between the direct and gateway verifiers", () => {
    const service = new HTTPTRQPService(new MockTRQPService("data/policies.json", "data/revocations.json"));
    expect(service.verifier.cache).toBe(service.cache);
    expect(service.gatewayVerifier.cache).toBe(service.cache);
  });
});
