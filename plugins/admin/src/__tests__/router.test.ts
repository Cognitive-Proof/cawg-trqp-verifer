import type { AddressInfo } from "node:net";
import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RegistryAdmin } from "../admin.js";
import { bearerTokenAdmins, createAdminRouter } from "../router.js";
import { InMemoryAdminStore } from "../store.js";
import { didKeyIdentity, ISSUE } from "./helpers.js";

const ADMIN_TOKEN = "test-admin-token";
let base = "";
let close: () => void;

beforeAll(async () => {
  const admin = new RegistryAdmin({ store: new InMemoryAdminStore(), requestable: [ISSUE] });
  const app = express();
  app.use("/registry", createAdminRouter(admin, { authenticateAdmin: bearerTokenAdmins({ [ADMIN_TOKEN]: "admin@example.com" }) }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/registry`;
  close = () => server.close();
});

afterAll(() => close());

async function call(path: string, init: { method?: string; body?: unknown; admin?: boolean } = {}) {
  const res = await fetch(base + path, {
    method: init.method ?? (init.body === undefined ? "GET" : "POST"),
    headers: {
      "content-type": "application/json",
      ...(init.admin ? { authorization: `Bearer ${ADMIN_TOKEN}` } : {}),
    },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
  // Test responses are asserted field by field.
  const body = (await res.json()) as any;
  return { status: res.status, type: res.headers.get("content-type") ?? "", body };
}

async function submitRequest(identity = didKeyIdentity()) {
  const { body: challenge } = await call("/challenges", { method: "POST" });
  return call("/requests", {
    body: { entity_id: identity.did, ...ISSUE, challenge: challenge.challenge, signature: identity.signRequest(challenge.challenge, ISSUE) },
  });
}

describe("createAdminRouter", () => {
  it("lists what can be requested", async () => {
    const { body } = await call("/permissions");
    expect(body.requestable).toEqual([ISSUE]);
  });

  it("runs request → approve → revoke over HTTP", async () => {
    const submitted = await submitRequest();
    expect(submitted.status).toBe(201);
    expect((await call(`/requests/${submitted.body.id}`)).body.status).toBe("pending");

    const pending = await call("/admin/requests?status=pending", { admin: true });
    expect(pending.body.map((r: { id: string }) => r.id)).toContain(submitted.body.id);

    const approved = await call(`/admin/requests/${submitted.body.id}/approve`, { body: { note: "ok" }, admin: true });
    expect(approved.status).toBe(200);
    expect(approved.body.grant).toMatchObject({ authorized: true, granted_by: "admin@example.com" });

    const revoked = await call(`/admin/grants/${approved.body.grant.id}/revoke`, { body: { reason: "test" }, admin: true });
    expect(revoked.body).toMatchObject({ authorized: false, revoked_by: "admin@example.com" });

    const audit = await call(`/admin/audit?subject_id=${approved.body.grant.id}`, { admin: true });
    expect(audit.body.map((e: { action: string }) => e.action)).toEqual(["grant.created", "grant.revoked"]);
  });

  it("requires an administrator for /admin", async () => {
    const res = await call("/admin/requests");
    expect(res.status).toBe(401);
    expect(res.type).toContain("application/problem+json");
  });

  it("answers refusals as problem details", async () => {
    const submitted = await submitRequest();
    await call(`/admin/requests/${submitted.body.id}/reject`, { body: {}, admin: true });
    const again = await call(`/admin/requests/${submitted.body.id}/approve`, { body: {}, admin: true });
    expect(again.status).toBe(409);
    expect(again.body).toMatchObject({ title: "Already decided", status: 409 });
  });

  it("validates request bodies", async () => {
    const res = await call("/requests", { body: { entity_id: "did:key:z6Mk" } });
    expect(res.status).toBe(400);
    expect(res.body.detail).toMatch(/authority_id/);
  });

  it("grants standing permissions directly", async () => {
    const service = didKeyIdentity();
    const res = await call("/admin/grants", { body: { entity_id: service.did, ...ISSUE, evidence: ["service"] }, admin: true });
    expect(res.status).toBe(201);
    expect((await call(`/admin/grants?entity_id=${encodeURIComponent(service.did)}&active=true`, { admin: true })).body).toHaveLength(1);
  });
});
