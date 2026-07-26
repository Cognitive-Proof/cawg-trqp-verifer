# @cognitiveproof/cawg-trqp-plugin-mongodb

MongoDB-backed `PolicyService` for [`cawg-trqp-refimpl`](../../README.md), using the official [`mongodb`](https://www.npmjs.com/package/mongodb) driver.

## Install

```bash
npm install @cognitiveproof/cawg-trqp-plugin-mongodb
```

## Usage

```ts
import { Verifier } from "cawg-trqp-refimpl";
import { MongoPolicyService } from "@cognitiveproof/cawg-trqp-plugin-mongodb";

const verifier = new Verifier({
  service: new MongoPolicyService({ uri: process.env.MONGO_URI, dbName: "trqp" }),
});
```

## Schema

Three collections, matching the JSON shape `MockTRQPService` reads from `data/policies.json` / `data/revocations.json` in the core package - migrating from the mock is a straightforward document copy:

- **`authorizations`**: `{ entity_id, authority_id, action, resource, context, authorized, expires, policy_epoch, evidence, reason, policy_requirements }`
- **`recognitions`**: `{ authority_id, recognized_authority_id, context, recognized, expires, policy_epoch, evidence, reason }`
- **`revocations`**: a single document `{ revoked_entities, policy_epoch, issued_at, channel }`

Collection names are configurable via `authorizationsCollection` / `recognitionsCollection` / `revocationsCollection` options.

**Context matching**: candidate documents are fetched by an exact match on `entity_id`/`authority_id`/`action`/`resource` (or `authority_id`/`recognized_authority_id`), then filtered in application code so every key in the stored `context` must match the request's context - the request may carry additional context keys. This intentionally mirrors `MockTRQPService`'s matching semantics rather than relying on MongoDB's exact-subdocument-equality query, which would reject a match whenever key order differs or the request supplies extra context.

## Not implemented in this reference scaffold

- Signed feed-descriptor evidence for the policy/revocation feeds (`feedDescriptorEvidence()` returns `{}`). Extend this class if your deployment needs it.
- Connection pooling/retry tuning beyond what the `mongodb` driver does by default.

## Configuration

```ts
new MongoPolicyService({
  uri: "mongodb://user:pass@host:27017",   // default: MONGO_URI env var, else mongodb://localhost:27017
  dbName: "trqp",                          // default: MONGO_DB_NAME env var, else the client's default database
});
```
