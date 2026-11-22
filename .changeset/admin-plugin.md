---
"@cognitiveproof/cawg-trqp-plugin-admin": minor
---

Add `@cognitiveproof/cawg-trqp-plugin-admin`: trust registry administration. Entities request a permission and prove control of their identifier's key (did:key Ed25519 built in); administrators approve, reject and revoke, with an audit log. `AdminPolicyService` answers TRQP authorization queries from the resulting grants and honours `context.time`, so revocation is not retroactive. Includes in-memory and MongoDB stores, an optional Express router, and `createAdminUI()`, an admin web page (built with Vite) for deciding requests, adding and revoking grants and reading the audit log.
