# @cognitiveproof/cawg-trqp-plugin-mysql

MySQL-backed `PolicyService` for [`cawg-trqp-refimpl`](../../README.md), using [`mysql2`](https://www.npmjs.com/package/mysql2).

## Install

```bash
npm install @cognitiveproof/cawg-trqp-plugin-mysql
```

## Usage

```ts
import { Verifier } from "cawg-trqp-refimpl";
import { MySQLPolicyService } from "@cognitiveproof/cawg-trqp-plugin-mysql";

const verifier = new Verifier({
  service: new MySQLPolicyService({ uri: process.env.MYSQL_URI }),
});
```

## Schema

```sql
CREATE TABLE authorizations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  entity_id VARCHAR(255) NOT NULL,
  authority_id VARCHAR(255) NOT NULL,
  action VARCHAR(255) NOT NULL,
  resource VARCHAR(255) NOT NULL,
  context JSON,
  authorized BOOLEAN NOT NULL,
  expires VARCHAR(64),
  policy_epoch VARCHAR(64),
  evidence JSON,
  reason VARCHAR(255),
  policy_requirements JSON,
  INDEX (entity_id, authority_id, action, resource)
);

CREATE TABLE recognitions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  authority_id VARCHAR(255) NOT NULL,
  recognized_authority_id VARCHAR(255) NOT NULL,
  context JSON,
  recognized BOOLEAN NOT NULL,
  expires VARCHAR(64),
  policy_epoch VARCHAR(64),
  evidence JSON,
  reason VARCHAR(255),
  INDEX (authority_id, recognized_authority_id)
);

-- Single-row table: this reference scaffold reads the first row it finds.
CREATE TABLE revocations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  revoked_entities JSON NOT NULL,
  policy_epoch VARCHAR(64),
  issued_at VARCHAR(64),
  channel VARCHAR(64)
);
```

Table names are configurable via `authorizationsTable` / `recognitionsTable` / `revocationsTable` options.

**Context matching**: candidate rows are fetched by an exact `WHERE` match on `entity_id`/`authority_id`/`action`/`resource` (or `authority_id`/`recognized_authority_id`), then filtered in application code so every key in the stored `context` JSON must match the request's context - the request may carry additional context keys. This intentionally mirrors `MockTRQPService`'s matching semantics rather than a JSON-equality SQL predicate, which would be both less portable across MySQL versions and sensitive to key order.

## Not implemented in this reference scaffold

- Signed feed-descriptor evidence for the policy/revocation feeds (`feedDescriptorEvidence()` returns `{}`).
- Connection pool tuning beyond `mysql2`'s defaults.

## Configuration

```ts
new MySQLPolicyService({ uri: "mysql://user:pass@host:3306/trqp" }); // default: MYSQL_URI env var, else mysql://root@localhost:3306/trqp
```
