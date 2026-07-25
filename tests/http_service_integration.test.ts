import { readFileSync } from "node:fs";
import { createServer } from "node:net";
import { spawn } from "node:child_process";
import { describe, expect, it } from "vitest";

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address && typeof address === "object") {
        const port = address.port;
        server.close(() => resolve(port));
      } else {
        server.close(() => reject(new Error("failed to allocate a free port")));
      }
    });
    server.on("error", reject);
  });
}

async function waitForHealth(url: string, attempts = 30): Promise<void> {
  for (let i = 0; i < attempts; i += 1) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1000) });
      if (response.status === 200) return;
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`service at ${url} never became healthy`);
}

describe("start_http_service script", () => {
  it("serves the verify endpoint end-to-end", async () => {
    const port = await freePort();
    const child = spawn(
      "npx",
      [
        "tsx",
        "scripts/start_http_service.ts",
        "--policy-path",
        "data/policies.json",
        "--revocation-path",
        "data/revocations.json",
        "--host",
        "127.0.0.1",
        "--port",
        String(port),
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );

    try {
      await waitForHealth(`http://127.0.0.1:${port}/health`);
      const payload = readFileSync("examples/verification_request.json", "utf-8");
      const response = await fetch(`http://127.0.0.1:${port}/trqp/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload,
      });
      const result = (await response.json()) as any;
      expect(["trusted", "trusted_cached"]).toContain(result.trust_outcome);
      expect(result.verification_mode).toBe("cached_online");
    } finally {
      child.kill();
    }
  }, 20000);
});
