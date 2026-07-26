# @cognitiveproof/cawg-trqp-plugin-postgres

Postgres-backed `PolicyService` for [`cawg-trqp-refimpl`](../../README.md), using [`pg`](https://www.npmjs.com/package/pg).

## Install

```bash
npm install @cognitiveproof/cawg-trqp-plugin-postgres
```

## Usage

```ts
import { Verifier } from "cawg-trqp-refimpl";
import { PostgresPolicyService } from "@cognitiveproof/cawg-trqp-plugin-postgres";

const verifier = new Verifier({
  service: new PostgresPolicyService({ uri: process.env.POSTGRES_URI }),
});
```

## Schema

```sql
CREATE TABLE authorizations (
  id SERIAL PRIMARY KEY,
  entity_id TEXT NOT NULL,
  authority_id TEXT NOT NULL,
  action TEXT NOT NULL,
  resource TEXT NOT NULL,
  context JSONB,
  authorized BOOLEAN NOT NULL,
  expires TEXT,
  policy_epoch TEXT,
  evidence JSONB,
  reason TEXT,
  policy_requirements JSONB
);
CREATE INDEX ON authorizations (entity_id, authority_id, action, resource);

CREATE TABLE recognitions (
  id SERIAL PRIMARY KEY,
  authority_id TEXT NOT NULL,
  recognized_authority_id TEXT NOT NULL,
  context JSONB,
  recognized BOOLEAN NOT NULL,
  expires TEXT,
  policy_epoch TEXT,
  evidence JSONB,
  reason TEXT
);
CREATE INDEX ON recognitions (authority_id, recognized_authority_id);

-- Single-row table: this reference scaffold reads the first row it finds.
CREATE TABLE revocations (
  id SERIAL PRIMARY KEY,
  revoked_entities JSONB NOT NULL,
  policy_epoch TEXT,
  issued_at TEXT,
  channel TEXT
);
```

Table names are configurable via `authorizationsTable` / `recognitionsTable` / `revocationsTable` options.

**Context matching**: candidate rows are fetched by an exact `WHERE` match on `entity_id`/`authority_id`/`action`/`resource` (or `authority_id`/`recognized_authority_id`), then filtered in application code so every key in the stored `context` JSONB must match the request's context - the request may carry additional context keys. This intentionally mirrors `MockTRQPService`'s matching semantics rather than a jsonb containment (`@>`) predicate, which would reject a match whenever the request supplies extra context keys the stored row has no opinion on.

## Not implemented in this reference scaffold

- Signed feed-descriptor evidence for the policy/revocation feeds (`feedDescriptorEvidence()` returns `{}`).
- Connection pool tuning beyond `pg`'s defaults.

## Configuration

```ts
new PostgresPolicyService({ uri: "postgres://user:pass@host:5432/trqp" }); // default: POSTGRES_URI env var, else postgres://localhost:5432/trqp
```
