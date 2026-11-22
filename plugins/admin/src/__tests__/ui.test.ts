import { mkdtempSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RegistryAdmin } from "../admin.js";
import { bearerTokenAdmins, createAdminRouter, createAdminUI } from "../router.js";
import { InMemoryAdminStore } from "../store.js";
import { ISSUE } from "./helpers.js";

let base = "";
let close: () => void;

beforeAll(async () => {
  // A stand-in for the Vite build, so these tests don't depend on it.
  const root = mkdtempSync(join(tmpdir(), "admin-ui-"));
  writeFileSync(join(root, "index.html"), "<!doctype html><title>Registry admin</title>");
  const admin = new RegistryAdmin({ store: new InMemoryAdminStore(), requestable: [ISSUE] });
  const app = express();
  app.use("/registry", createAdminUI({ root }), createAdminRouter(admin, { authenticateAdmin: bearerTokenAdmins({ token: "admin" }) }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/registry`;
  close = () => server.close();
});

afterAll(() => close());

describe("createAdminUI", () => {
  it("serves the page with a restrictive content security policy", async () => {
    const res = await fetch(`${base}/ui/`);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Registry admin");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'self'");
    expect(res.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
  });

  it("redirects to the directory form, relative to the mount point", async () => {
    const res = await fetch(`${base}/ui?x=1`, { redirect: "manual" });
    expect(res.status).toBe(301);
    expect(res.headers.get("location")).toBe("ui/?x=1");
  });

  it("leaves the API alone", async () => {
    const res = await fetch(`${base}/permissions`);
    expect(await res.json()).toEqual({ requestable: [ISSUE] });
    expect((await fetch(`${base}/ui/missing.js`)).status).toBe(404);
  });
});
