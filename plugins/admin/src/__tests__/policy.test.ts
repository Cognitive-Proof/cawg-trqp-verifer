import { describe, expect, it } from "vitest";
import { RegistryAdmin } from "../admin.js";
import { AdminPolicyService } from "../policy.js";
import { InMemoryAdminStore } from "../store.js";
import { clock, didKeyIdentity, ISSUE } from "./helpers.js";

async function approvedProducer(grantTtlSeconds: number | null = null) {
  const time = clock("2026-11-01T00:00:00Z");
  const store = new InMemoryAdminStore();
  const admin = new RegistryAdmin({ store, requestable: [ISSUE], now: time.now, grantTtlSeconds });
  const policy = new AdminPolicyService({ store, now: time.now });
  const producer = didKeyIdentity();
  const challenge = await admin.createChallenge();
  const request = await admin.requestAccess({
    entity_id: producer.did,
    ...ISSUE,
    challenge: challenge.id,
    signature: producer.signRequest(challenge.id, ISSUE),
  });
  const { grant } = await admin.approve(request.id, "admin@example.com");
  const ask = (context: Record<string, unknown> = {}) =>
    policy.authorization(producer.did, ISSUE.authority_id, ISSUE.action, ISSUE.resource, context);
  return { admin, policy, time, grant, ask, producer };
}

describe("AdminPolicyService", () => {
  it("authorizes an entity with an active grant", async () => {
    const { ask, grant } = await approvedProducer();
    const answer = await ask();
    expect(answer.authorized).toBe(true);
    expect(answer.evidence[0]).toBe(`grant:${grant.id}`);
  });

  it("answers for the time in context.time, so revocation isn't retroactive", async () => {
    const { admin, time, grant, ask } = await approvedProducer();
    time.advance(7 * 24 * 3600); // revoke on 2026-11-08
    await admin.revoke(grant.id, "admin@example.com");

    expect(await ask()).toMatchObject({ authorized: false, reason: "revoked" });
    // A credential issued on 2026-11-05, while the grant was active, still checks out.
    expect(await ask({ time: "2026-11-05T09:30:00Z" })).toMatchObject({ authorized: true });
    // One issued after the revocation does not.
    expect(await ask({ time: "2026-11-09T00:00:00Z" })).toMatchObject({ authorized: false, reason: "revoked" });
  });

  it("is not authorized before the grant existed", async () => {
    const { ask } = await approvedProducer();
    expect(await ask({ time: "2026-10-01T00:00:00Z" })).toMatchObject({ authorized: false, reason: "not_yet_granted" });
  });

  it("honours grant expiry", async () => {
    const { ask, grant } = await approvedProducer(30 * 24 * 3600);
    expect(grant.expires).toBe("2026-12-01T00:00:00.000Z");
    expect(await ask({ time: "2026-11-30T23:59:59Z" })).toMatchObject({ authorized: true, expires: grant.expires });
    expect(await ask({ time: "2026-12-01T00:00:00Z" })).toMatchObject({ authorized: false, reason: "expired" });
  });

  it("does not authorize unknown entities or other actions", async () => {
    const { policy, producer } = await approvedProducer();
    expect(await policy.authorization(didKeyIdentity().did, ISSUE.authority_id, "issue", ISSUE.resource, {})).toMatchObject({
      authorized: false,
      reason: "no_matching_policy",
    });
    expect(await policy.authorization(producer.did, ISSUE.authority_id, "publish-status", ISSUE.resource, {})).toMatchObject({
      authorized: false,
      reason: "no_matching_policy",
    });
  });

  it("refuses an unparseable context.time", async () => {
    const { ask } = await approvedProducer();
    expect(await ask({ time: "last tuesday" })).toMatchObject({ authorized: false, reason: "invalid_context_time" });
  });

  it("reports a live revocation feed", async () => {
    const { policy } = await approvedProducer();
    expect(await policy.revocationStatus()).toMatchObject({ channel: "live", age_seconds: 0, revoked_entities: [] });
  });
});
