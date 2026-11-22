# @cognitiveproof/cawg-trqp-plugin-admin

## 0.1.1

### Patch Changes

- [#4](https://github.com/Cognitive-Proof/cawg-trqp-verifer/pull/4) [`14d65ca`](https://github.com/Cognitive-Proof/cawg-trqp-verifer/commit/14d65cab1de01788653ff9a6062634916e397ef1) Thanks [@mrappard](https://github.com/mrappard)! - First release published from CI through npm trusted publishing, with provenance. No code changes from 0.1.0.

## 0.1.0

### Minor Changes

- [#1](https://github.com/Cognitive-Proof/cawg-trqp-verifer/pull/1) [`6b838e5`](https://github.com/Cognitive-Proof/cawg-trqp-verifer/commit/6b838e516c18eff8b306291927a7f6655c624010) Thanks [@mrappard](https://github.com/mrappard)! - Add `@cognitiveproof/cawg-trqp-plugin-admin`: trust registry administration. Entities request a permission and prove control of their identifier's key (did:key Ed25519 built in); administrators approve, reject and revoke, with an audit log. `AdminPolicyService` answers TRQP authorization queries from the resulting grants and honours `context.time`, so revocation is not retroactive. Includes in-memory and MongoDB stores, an optional Express router, and `createAdminUI()`, an admin web page (built with Vite) for deciding requests, adding and revoking grants and reading the audit log.
