// A throwaway registry for working on the admin page: an in-memory store
// with one pending request and one standing grant, the admin router at
// /registry and the built page at /registry/ui/. Run it with `npm run
// dev:server`, then either open /registry/ui/ (after `npm run build`) or run
// `npm run dev:ui` for Vite with live reload.

import { fileURLToPath } from "node:url";
import express from "express";
import { didKeyIdentity } from "../src/__tests__/helpers.js";
import { RegistryAdmin } from "../src/admin.js";
import { bearerTokenAdmins, createAdminRouter, createAdminUI } from "../src/router.js";
import { InMemoryAdminStore } from "../src/store.js";

const port = Number(process.env.PORT ?? 8080);
const token = process.env.ADMIN_TOKEN ?? "dev-admin-token";
const authority = "did:web:registry.example";
const issue = { authority_id: authority, action: "issue", resource: "ExampleGuildLikenessConsentCredential" };

const admin = new RegistryAdmin({
  store: new InMemoryAdminStore(),
  requestable: [issue, { authority_id: authority, action: "publish-status", resource: "BitstringStatusListCredential" }],
});

const applicant = didKeyIdentity();
const challenge = await admin.createChallenge();
await admin.requestAccess({
  entity_id: applicant.did,
  ...issue,
  challenge: challenge.id,
  signature: applicant.signRequest(challenge.id, issue),
  applicant: { name: "Ada Producer", organization: "Example Films", email: "ada@example.com", note: "Casting for a short film" },
});
await admin.grantDirectly(didKeyIdentity().did, { ...issue, action: "publish-status", resource: "BitstringStatusListCredential" }, "seed", [
  "status list service key",
]);

const app = express();
// Run from source, so point at the build rather than the packaged default.
const root = fileURLToPath(new URL("../dist/ui/", import.meta.url));
app.use("/registry", createAdminUI({ root }), createAdminRouter(admin, { authenticateAdmin: bearerTokenAdmins({ [token]: "dev-admin" }) }));
app.listen(port, () => {
  console.log(`Registry admin on http://localhost:${port}/registry/ui/ (token: ${token})`);
});
