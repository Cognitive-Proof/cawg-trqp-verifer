import { describe, expect, it } from "vitest";
import { AdminError, RegistryAdmin, type AccessRequestInput } from "../admin.js";
import { InMemoryAdminStore } from "../store.js";
import { clock, didKeyIdentity, ISSUE, PUBLISH_STATUS } from "./helpers.js";

function setup(options: Partial<ConstructorParameters<typeof RegistryAdmin>[0]> = {}) {
  const time = clock();
  const admin = new RegistryAdmin({ store: new InMemoryAdminStore(), requestable: [ISSUE], now: time.now, ...options });
  return { admin, time };
}

async function signedRequest(admin: RegistryAdmin, identity = didKeyIdentity(), permission = ISSUE): Promise<AccessRequestInput> {
  const challenge = await admin.createChallenge();
  return {
    entity_id: identity.did,
    ...permission,
    applicant: { name: "Pat", organization: "Example Films" },
    challenge: challenge.id,
    signature: identity.signRequest(challenge.id, permission),
  };
}

async function refusal(promise: Promise<unknown>): Promise<AdminError> {
  const err = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(AdminError);
  return err as AdminError;
}

describe("RegistryAdmin requests", () => {
  it("accepts a request signed with the entity's key", async () => {
    const { admin } = setup();
    const request = await admin.requestAccess(await signedRequest(admin));

    expect(request).toMatchObject({ status: "pending", action: "issue", applicant: { organization: "Example Films" } });
    expect(request.evidence[0]).toMatch(/^proof-of-possession:/);
    expect(await admin.listRequests({ status: "pending" })).toHaveLength(1);
  });

  it("refuses a signature made with a different key", async () => {
    const { admin } = setup();
    const input = await signedRequest(admin);
    const challenge = await admin.createChallenge();
    const impostor = didKeyIdentity();
    const err = await refusal(
      admin.requestAccess({ ...input, challenge: challenge.id, signature: impostor.signRequest(challenge.id, ISSUE, input.entity_id) }),
    );
    expect(err.status).toBe(403);
  });

  it("binds the signature to the permission requested", async () => {
    const { admin } = setup({ requestable: [ISSUE, PUBLISH_STATUS] });
    const identity = didKeyIdentity();
    const challenge = await admin.createChallenge();
    const signedForIssue = identity.signRequest(challenge.id, ISSUE);
    const err = await refusal(
      admin.requestAccess({ entity_id: identity.did, ...PUBLISH_STATUS, challenge: challenge.id, signature: signedForIssue }),
    );
    expect(err.status).toBe(403);
  });

  it("uses each challenge once and only while fresh", async () => {
    const { admin, time } = setup();
    const input = await signedRequest(admin);
    await admin.requestAccess(input);
    expect((await refusal(admin.requestAccess(input))).status).toBe(400);

    const stale = await signedRequest(admin);
    time.advance(301);
    expect((await refusal(admin.requestAccess(stale))).status).toBe(400);
  });

  it("refuses permissions that are not requestable", async () => {
    const { admin } = setup();
    expect((await refusal(admin.requestAccess(await signedRequest(admin, undefined, PUBLISH_STATUS)))).status).toBe(404);
  });

  it("refuses identifiers no verifier supports", async () => {
    const { admin } = setup();
    const input = await signedRequest(admin);
    expect((await refusal(admin.requestAccess({ ...input, entity_id: "did:web:producer.example" }))).status).toBe(400);
  });

  it("returns the pending request instead of creating a duplicate", async () => {
    const { admin } = setup();
    const identity = didKeyIdentity();
    const first = await admin.requestAccess(await signedRequest(admin, identity));
    const second = await admin.requestAccess(await signedRequest(admin, identity));
    expect(second.id).toBe(first.id);
  });

  it("runs the deployment's applicant check and records its evidence", async () => {
    const { admin } = setup({
      checkApplicant: async (input) => {
        if (!input.applicant?.email) throw new AdminError(403, "Certificate required", "No certificate email");
        return [`certificate-email:${input.applicant.email}`];
      },
    });
    expect((await refusal(admin.requestAccess(await signedRequest(admin)))).status).toBe(403);

    const input = await signedRequest(admin);
    const request = await admin.requestAccess({ ...input, applicant: { email: "pat@example.com" } });
    expect(request.evidence).toContain("certificate-email:pat@example.com");
  });
});

describe("RegistryAdmin decisions", () => {
  it("approving creates a grant carrying the request's evidence", async () => {
    const { admin, time } = setup({ policyEpoch: "2026-Q4" });
    const request = await admin.requestAccess(await signedRequest(admin));
    const { request: approved, grant } = await admin.approve(request.id, "admin@example.com", "known producer");

    expect(approved).toMatchObject({ status: "approved", decided_by: "admin@example.com", grant_id: grant.id });
    expect(grant).toMatchObject({
      entity_id: request.entity_id,
      ...ISSUE,
      authorized: true,
      granted_at: time.iso(),
      revoked_at: null,
      policy_epoch: "2026-Q4",
      request_id: request.id,
    });
    expect(grant.evidence).toEqual(expect.arrayContaining([`request:${request.id}`, "approved-by:admin@example.com"]));
  });

  it("a request is decided once", async () => {
    const { admin } = setup();
    const request = await admin.requestAccess(await signedRequest(admin));
    await admin.reject(request.id, "admin@example.com", "not a member");
    expect((await refusal(admin.approve(request.id, "other@example.com"))).status).toBe(409);
    expect((await refusal(admin.approve("missing", "admin@example.com"))).status).toBe(404);
  });

  it("an authorized entity can't request the same permission again", async () => {
    const { admin } = setup();
    const identity = didKeyIdentity();
    const request = await admin.requestAccess(await signedRequest(admin, identity));
    await admin.approve(request.id, "admin@example.com");
    expect((await refusal(admin.requestAccess(await signedRequest(admin, identity)))).status).toBe(409);
  });

  it("revoking keeps the grant's history and happens once", async () => {
    const { admin, time } = setup();
    const request = await admin.requestAccess(await signedRequest(admin));
    const { grant } = await admin.approve(request.id, "admin@example.com");
    time.advance(3600);
    const revoked = await admin.revoke(grant.id, "admin@example.com", "left the guild");

    expect(revoked).toMatchObject({ authorized: false, reason: "revoked", revoked_at: time.iso(), granted_at: grant.granted_at });
    expect(revoked.evidence).toContain("revocation-reason:left the guild");
    expect((await refusal(admin.revoke(grant.id, "admin@example.com"))).status).toBe(409);
    expect(await admin.listGrants({ active: true })).toHaveLength(0);
  });

  it("grants standing permissions directly, once", async () => {
    const { admin } = setup();
    const service = didKeyIdentity();
    const first = await admin.grantDirectly(service.did, PUBLISH_STATUS, "operator", ["service:status-lists"]);
    const second = await admin.grantDirectly(service.did, PUBLISH_STATUS, "operator");
    expect(second.id).toBe(first.id);
    expect(first.evidence).toEqual(["granted-by:operator", "service:status-lists"]);
  });

  it("records every step in the audit log", async () => {
    const { admin } = setup();
    const request = await admin.requestAccess(await signedRequest(admin));
    const { grant } = await admin.approve(request.id, "admin@example.com");
    await admin.revoke(grant.id, "admin@example.com");

    expect((await admin.auditLog()).map((e) => e.action)).toEqual([
      "request.created",
      "request.approved",
      "grant.created",
      "grant.revoked",
    ]);
    expect((await admin.auditLog(grant.id)).map((e) => e.actor)).toEqual(["admin@example.com", "admin@example.com"]);
  });
});
