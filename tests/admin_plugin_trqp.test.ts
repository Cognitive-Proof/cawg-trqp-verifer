import { generateKeyPairSync, sign } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { HTTPTRQPService } from "../src/http_service.js";
import { AdminPolicyService, InMemoryAdminStore, RegistryAdmin, accessRequestMessage } from "../plugins/admin/src/index.js";
import { bearerTokenAdmins, createAdminRouter } from "../plugins/admin/src/router.js";

// The admin plugin end to end: the registry's TRQP endpoints answer from the
// grants its admin API manages, both mounted on one HTTPTRQPService app.

const AUTHORITY = "did:web:registry.example";
const ISSUE = { authority_id: AUTHORITY, action: "issue", resource: "ExampleGuildLikenessConsentCredential" };

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function didKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  let n = 0n;
  for (const b of [0xed, 0x01, ...Buffer.from(publicKey.export({ format: "jwk" }).x as string, "base64url")]) n = (n << 8n) | BigInt(b);
  let encoded = "";
  while (n > 0n) {
    encoded = BASE58[Number(n % 58n)] + encoded;
    n /= 58n;
  }
  const did = `did:key:z${encoded}`;
  return { did, sign: (challenge: string) => sign(null, accessRequestMessage(challenge, did, ISSUE), privateKey).toString("base64") };
}

describe("admin plugin behind HTTPTRQPService", () => {
  let baseUrl: string;
  let server: ReturnType<HTTPTRQPService["app"]["listen"]>;

  beforeEach(() => {
    const store = new InMemoryAdminStore();
    const admin = new RegistryAdmin({ store, requestable: [ISSUE] });
    const service = new HTTPTRQPService(new AdminPolicyService({ store }));
    service.app.use("/registry", createAdminRouter(admin, { authenticateAdmin: bearerTokenAdmins({ secret: "admin@example.com" }) }));
    server = service.app.listen(0);
    baseUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  });

  afterEach(() => {
    server.close();
  });

  async function post(path: string, body: unknown, admin = false) {
    const res = await fetch(baseUrl + path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(admin ? { Authorization: "Bearer secret" } : {}) },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: (await res.json()) as Record<string, any> };
  }

  const query = (entity: string, time?: string) =>
    post("/authorization", { entity_id: entity, ...ISSUE, ...(time ? { context: { time } } : {}) });

  it("answers TRQP authorization queries from approved and revoked grants", async () => {
    const producer = didKey();
    expect((await query(producer.did)).body).toMatchObject({ authorized: false, reason: "no_matching_policy" });

    const { body: challenge } = await post("/registry/challenges", {});
    const { body: request } = await post("/registry/requests", {
      entity_id: producer.did,
      ...ISSUE,
      challenge: challenge.challenge,
      signature: producer.sign(challenge.challenge),
    });
    const { body: approved } = await post(`/registry/admin/requests/${request.id}/approve`, {}, true);
    const grantedAt: string = approved.grant.granted_at;

    // A TRQP 2.0 authorization response: echo fields, decision, time_evaluated.
    const allowed = await query(producer.did);
    expect(allowed.status).toBe(200);
    expect(allowed.body).toMatchObject({ entity_id: producer.did, ...ISSUE, authorized: true });
    expect(typeof allowed.body.time_evaluated).toBe("string");

    await new Promise((resolve) => setTimeout(resolve, 5));
    await post(`/registry/admin/grants/${approved.grant.id}/revoke`, { reason: "left" }, true);

    expect((await query(producer.did)).body).toMatchObject({ authorized: false, reason: "revoked" });
    // A point-in-time query for while the grant was active is still authorized.
    const before = await query(producer.did, new Date(Date.parse(grantedAt) + 1).toISOString());
    expect(before.body).toMatchObject({ authorized: true, time_requested: expect.any(String) });
  });
});
