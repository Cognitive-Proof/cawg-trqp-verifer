# @cognitiveproof/cawg-trqp-plugin-admin

Trust registry administration for [`cawg-trqp-refimpl`](../../README.md). The query side of TRQP answers "is this entity authorized?"; this plugin manages *who becomes authorized*:

- **Access requests.** An entity asks for a permission (`authority_id`, `action`, `resource`) and proves it controls its identifier's key by signing a single-use challenge.
- **Approval.** Administrators approve, reject and revoke. Every step is recorded in an audit log.
- **TRQP answers.** `AdminPolicyService` is a `PolicyService` over the resulting grants, so `HTTPTRQPService` serves them as TRQP authorization queries.
- **Time-aware answers.** A query with `context.time` is answered as of that moment, so revoking a grant stops authorization from then on without changing the answer for earlier times. For example, a consent credential issued while its issuer was authorized stays valid after the issuer is revoked.

## Install

```bash
npm install @cognitiveproof/cawg-trqp-plugin-admin
```

`express` is an optional peer dependency, needed only for the HTTP router.

## Usage

```ts
import { HTTPTRQPService } from "@cognitiveproof/cawg-trqp";
import { AdminPolicyService, MongoAdminStore, RegistryAdmin } from "@cognitiveproof/cawg-trqp-plugin-admin";
import { bearerTokenAdmins, createAdminRouter } from "@cognitiveproof/cawg-trqp-plugin-admin/router";

const store = new MongoAdminStore({ uri: process.env.MONGO_URI, dbName: "trqp" });
const admin = new RegistryAdmin({
  store,
  requestable: [{ authority_id: "did:web:registry.example", action: "issue", resource: "ExampleGuildLikenessConsentCredential" }],
});

const service = new HTTPTRQPService(new AdminPolicyService({ store })); // POST /authorization, /recognition
service.app.use("/registry", createAdminRouter(admin, { authenticateAdmin: bearerTokenAdmins({ [process.env.ADMIN_TOKEN!]: "admin" }) }));
service.run("0.0.0.0", 8080);
```

## Requesting access

1. `POST /registry/challenges` returns `{ challenge, expires_at }` (default lifetime 5 minutes).
2. The entity signs the UTF-8 bytes of:
   ```
   "trqp-access-request:" + JSON.stringify([challenge, entity_id, authority_id, action, resource])
   ```
   Binding the challenge to the exact permission stops a signature from being replayed for a different request.
3. `POST /registry/requests` with `{ entity_id, authority_id, action, resource, challenge, signature, applicant? }`. The signature is base64 or base64url.

`did:key` Ed25519 identifiers are verified out of the box. Pass `proofVerifiers` to support other methods. Pass `checkApplicant` to add deployment-specific checks, for example requiring a certificate from your CA. It runs after proof of possession, refuses by throwing an `AdminError`, and can return evidence strings to record on the request.

## HTTP API

| Method | Path | Who | |
|---|---|---|---|
| GET | `/permissions` | anyone | What can be requested |
| POST | `/challenges` | anyone | A single-use challenge |
| POST | `/requests` | anyone | Submit a signed request |
| GET | `/requests/:id` | anyone | A request's status |
| GET | `/admin/requests?status=&entity_id=&authority_id=` | admin | List requests |
| POST | `/admin/requests/:id/approve` · `/reject` | admin | Decide, with an optional `{ note }` |
| GET | `/admin/grants?entity_id=&authority_id=&action=&resource=&active=` | admin | List grants |
| POST | `/admin/grants` | admin | Grant directly (standing grants, e.g. a service key) |
| POST | `/admin/grants/:id/revoke` | admin | Revoke, with an optional `{ reason }` |
| GET | `/admin/audit?subject_id=` | admin | Audit log |

Errors are RFC 7807 problem details, like the core service's. `authenticateAdmin` decides who is an administrator. The name it returns is recorded on decisions and in the audit log; `bearerTokenAdmins()` is a minimal implementation.

## Storage

`InMemoryAdminStore` suits tests and single-instance demos. `MongoAdminStore` uses four collections, each with a configurable name:

- `authorizations`: grants. This is the collection the MongoDB plugin's `MongoPolicyService` reads, and grants keep its document shape (`entity_id`, `authority_id`, `action`, `resource`, `context`, `authorized`, `expires`, `policy_epoch`, `evidence`, `reason`), plus `granted_at`, `revoked_at` and `request_id`. `MongoPolicyService` can therefore read them too, but only `AdminPolicyService` answers point-in-time queries.
- `access_requests`, `access_challenges`, `admin_audit`.

It uses only equality filters and single-document conditional updates (`findOneAndUpdate`, `findOneAndDelete`), so it also runs on MongoDB-compatible backends such as Firestore.

## Answers

`AdminPolicyService.authorization()` returns `authorized: true` with the grant's `evidence`, `expires` and `policy_epoch`, or `authorized: false` with one of these reasons:

- `no_matching_policy`: no grant ever existed for this entity and permission;
- `not_yet_granted`;
- `revoked`;
- `expired`;
- `invalid_context_time`.

Recognition queries go to an optional `recognition` `PolicyService`, and are otherwise not recognized.
