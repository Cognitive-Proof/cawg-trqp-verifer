import { Command } from "commander";
import { auditBundleToDict, buildAuditBundle } from "../src/audit.js";
import { canonicalJsonText } from "../src/jsoncanon.js";
import { createVerificationRequest, type VerificationRequest } from "../src/models.js";
import { MockTRQPService } from "../src/mock_service.js";
import { loadProfile } from "../src/profile.js";
import { loadJson } from "../src/validation.js";
import { Verifier } from "../src/verifier.js";

const program = new Command();
program
  .description("Rebuild and compare a deterministic CAWG-TRQP audit bundle fixture")
  .argument("<expected_bundle>", "Path to expected audit bundle fixture JSON")
  .option("--request <path>", "Path to verification request JSON", "examples/verification_request.json")
  .option("--policies <path>", "Path to policy data JSON", "data/policies.json")
  .option("--revocations <path>", "Path to revocation data JSON", "data/revocations.json")
  .option("--exported-at <timestamp>", "Deterministic timestamp override", "2026-03-31T00:00:00Z")
  .parse(process.argv);

const [expectedBundlePath] = program.args;
const opts = program.opts();

const request = createVerificationRequest(loadJson(opts.request) as unknown as VerificationRequest);
const profile = loadProfile("standard");
const verifier = new Verifier({ service: new MockTRQPService(opts.policies, opts.revocations) });
const result = await verifier.verify(request, profile);
const actual = auditBundleToDict(
  buildAuditBundle(request, result, {
    profile,
    exportedAt: opts.exportedAt,
    policyPath: opts.policies,
    revocationPath: opts.revocations,
  }),
);
const expected = loadJson(expectedBundlePath);

if (canonicalJsonText(actual) !== canonicalJsonText(expected)) {
  console.log(JSON.stringify({ matches: false, expected, actual }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({ matches: true, bundle_id: actual.bundle_id ?? null }, null, 2));
