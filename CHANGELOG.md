# @cognitiveproof/cawg-trqp

## 0.17.1

### Patch Changes

- Bring `HTTPTRQPService` into conformance with the TRQP v2.0 approved HTTPS binding, per an external audit against the spec:

  - **Bare paths**: Authorization and Recognition queries now live at `POST /authorization` and `POST /recognition`, replacing the non-conformant `/trqp/authorization` and `/trqp/recognition`. (`/trqp/gateway/authorization`, `/trqp/verify`, and `/trqp/audit-bundle` are this library's own extensions beyond the base spec and are unchanged.)
  - **Recognition Query schema**: `PolicyService.recognition()` now takes `(entityId, authorityId, action, resource, context)`, matching the v2 spec's Recognition Query — this replaced the earlier authority-to-authority `(authorityId, recognizedAuthorityId, context)` shape. All three DB-backed plugins (`mongodb`, `mysql`, `postgres`) have been updated to match; their `recognitions` table/collection schema changed accordingly (see each plugin's README for the new column/field names).
  - **RFC 7807 Problem Details**: every HTTP error response (400/403/413/415/500) is now `{type, title, status, detail}` with `Content-Type: application/problem+json`, replacing the previous ad hoc `{error, message}` shape.
  - **Response schema**: Authorization/Recognition responses now echo `entity_id`, `authority_id`, `action`, `resource`, and include `time_evaluated` (RFC 3339), all required by the v2 response schema.

  Also fixes a crash: a malformed request body no longer produces a bare 502 with no detail — errors are now typed Problem Details responses, and the previous catch-all 502 for unexpected `PolicyService` failures is now a spec-correct 500.
