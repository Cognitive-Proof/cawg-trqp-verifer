# cawg-trqp-refimpl (TypeScript)

A TypeScript port of [`cawg-trqp-verifier-refimpl`](https://github.com/sankarshanmukhopadhyay/cawg-trqp-verifier-refimpl), the reference implementation for CAWG + TRQP integration. This port preserves the original's behavior byte-for-byte where it matters: canonical JSON hashing, Ed25519 signing/verification, and verifier decision logic have all been cross-checked against the Python implementation (see [Fidelity notes](#fidelity-notes)).

## What this is

A reference verifier for evaluating CAWG/C2PA manifest trust signals against TRQP-governed policy, with:

- A **verifier core** (`src/verifier.ts`) supporting online, cached, gateway-mediated, and offline/snapshot verification modes
- **Ed25519-signed feed descriptors, snapshots, and audit bundles**, using Node's native `node:crypto`
- An **Express HTTP service** exposing authorization, recognition, verification, and audit-bundle endpoints
- A **CLI** (`src/cli.ts`) for one-off verification runs and audit-bundle export
- **Deterministic replay**: audit bundles carry enough evidence (pinned policy/revocation feed digests, transport metadata, profile) to be replayed and independently re-verified later

## Requirements

- Node.js >= 20

## Install

```bash
npm install
```

## Build

```bash
npm run build      # compiles src/ -> dist/
npm run typecheck   # type-checks src/, scripts/, and tests/ without emitting
```

## Test

```bash
npm test
```

77 tests across 20 files, ported from the Python `pytest` suite, run against the same JSON fixtures/conformance vectors as the original.

## Run

```bash
# CLI: verify a manifest fixture
npm run verify -- --fixture examples/fixtures/cawg_manifest_minimal.json

# HTTP service
npm run serve -- --policy-path data/policies.json --revocation-path data/revocations.json --port 5000

# Demo script (a few canned verification scenarios)
npm run demo
```

## Scripts

| Command | Purpose |
|---|---|
| `npm run validate:examples` | Validate all `examples/` and `fixtures/` JSON against their schemas |
| `npm run validate:feed-descriptors` | Validate signed feed descriptors (signature, digest, authority) |
| `npm run validate:audit-bundle -- <bundle.json>` | Validate an audit bundle's schema, digest, and attestation |
| `npm run validate:photography-contest` | Validate the photography-contest example end to end |
| `npm run replay:audit-bundle -- <bundle.json>` | Replay an audit bundle and compare against its recorded result |
| `npm run sign:audit-bundle -- <bundle.json> <key.pem> --key-id <id>` | Sign an audit bundle with an Ed25519 key |
| `npm run sign:snapshot -- <snapshot.json> <key.pem> --key-id <id>` | Sign an offline snapshot with an Ed25519 key |
| `npm run check:reproducibility -- <expected.json>` | Rebuild a bundle and diff against a pinned fixture |
| `npm run export:conformance-pack -- --check` | Verify `conformance/assurance-suite-manifest.json` is current |
| `npm run validate` | Run the example/feed-descriptor/photography-contest checks plus the test suite |

## Project structure

```
src/            library source (verifier, mock service, gateway, profile, audit,
                replay, feed descriptors, attestation, HTTP service, CLI, ...)
scripts/        standalone CLI utilities (validation, signing, replay, demo)
tests/          Vitest suite
data/           policy/revocation/snapshot/trust-anchor fixtures
examples/       request/response/manifest/feed-descriptor examples
fixtures/       profile-bound conformance fixtures (request -> expected result)
profiles/       built-in verification profiles (standard, edge, high_assurance) + overlays
schemas/        JSON Schemas (Draft 2020-12) for all wire formats
conformance/    assurance-suite manifest and compatibility matrix
```

## Library usage

```ts
import { Verifier, MockTRQPService, loadManifestFixture } from "cawg-trqp-refimpl";

const request = loadManifestFixture("examples/fixtures/cawg_manifest_minimal.json", "did:web:media-registry.example");
const verifier = new Verifier({ service: new MockTRQPService("data/policies.json", "data/revocations.json") });
const result = verifier.verify(request, "standard");
```

## Fidelity notes

This port was validated against the Python reference implementation, not just translated:

- **Canonical JSON**: Python's `json.dumps(sort_keys=True, separators=(",", ":"))` is replicated exactly, in both its `ensure_ascii=False` form (used for `bundle_digest_sha256`) and its `ensure_ascii=True` form (used for signing payloads) — confirmed byte-for-byte against Python output.
- **Ed25519**: signing/verification via `node:crypto` uses the same PEM key format as Python's `cryptography` library. A bundle signed by this TypeScript CLI was verified successfully by the Python verifier, and vice versa; `bundle_digest_sha256`, `bundle_id`, and signature bytes matched exactly for identical input.
- **Verifier logic**: online/edge/gateway verification modes, transport and revocation freshness enforcement, and process-proof appraisal all match the Python test suite's assertions.
- **Known cosmetic difference**: JSON key ordering in pretty-printed output can differ from the Python implementation's field order (JSON objects are unordered, so this doesn't affect hashing, signing, or schema validation).

### Not ported

A handful of Python scripts and tests validate the *documentation and governance content* of the original repository (its full `docs/` tree, `governance/*.yaml` registers, `api/openapi.json`, release-checksum manifests) rather than verifier logic. Those weren't duplicated here since this port focuses on the library, not the documentation tree. See the original repository if you need those.

## License

MIT — see [LICENSE](./LICENSE). Ported from [`cawg-trqp-verifier-refimpl`](https://github.com/sankarshanmukhopadhyay/cawg-trqp-verifier-refimpl).
