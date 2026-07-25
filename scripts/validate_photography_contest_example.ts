import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { createAjv } from "../src/ajv.js";
import { loadFeedDescriptor, validateFeedDescriptor } from "../src/feed_descriptor.js";
import { replayAuditBundle } from "../src/replay.js";
import { loadJson } from "../src/validation.js";

const EXAMPLE = "examples/photography_contest";

function validateSchema(schemaName: string, instancePath: string): string[] {
  const validate = createAjv().compile(loadJson(path.join("schemas", schemaName)));
  const instance = loadJson(instancePath);
  if (validate(instance)) return [];
  return (validate.errors ?? []).map(
    (err) => `${instancePath}: ${err.instancePath.replace(/^\//, "") || "<root>"}: ${err.message}`,
  );
}

const failures: string[] = [];
const required = [
  "submission.json",
  "contest_policy_feed.json",
  "contest_revocation_feed.json",
  "policy-feed.signed.json",
  "revocation-feed.signed.json",
  "trust_anchors.json",
  "decision_receipt.json",
  "replay_bundle.json",
];
for (const name of required) {
  if (!existsSync(path.join(EXAMPLE, name))) {
    failures.push(`missing required example artifact: ${name}`);
  }
}

if (failures.length) {
  console.log("validate_photography_contest_example.ts: FAIL");
  for (const failure of failures) console.log(` - ${failure}`);
  process.exit(1);
}

failures.push(...validateSchema("decision-receipt.schema.json", path.join(EXAMPLE, "decision_receipt.json")));
failures.push(...validateSchema("audit-bundle.schema.json", path.join(EXAMPLE, "replay_bundle.json")));

const trustAnchors = loadJson(path.join(EXAMPLE, "trust_anchors.json"));
const policyBody = readFileSync(path.join(EXAMPLE, "contest_policy_feed.json"), "utf-8");
const revocationBody = readFileSync(path.join(EXAMPLE, "contest_revocation_feed.json"), "utf-8");
const expectedAuthorities = new Set(["did:web:media-registry.example"]);
const policyReport = validateFeedDescriptor(
  loadFeedDescriptor(path.join(EXAMPLE, "policy-feed.signed.json")),
  policyBody,
  { trustAnchors, expectedAuthorities },
);
const revocationReport = validateFeedDescriptor(
  loadFeedDescriptor(path.join(EXAMPLE, "revocation-feed.signed.json")),
  revocationBody,
  { trustAnchors, expectedAuthorities },
);
for (const [label, report] of [
  ["policy", policyReport],
  ["revocation", revocationReport],
] as const) {
  if (report.reason_code !== "fresh") {
    failures.push(`${label} descriptor is not fresh: ${report.reason_code}; ${JSON.stringify(report.violations)}`);
  }
}

const replayReport = replayAuditBundle(loadJson(path.join(EXAMPLE, "replay_bundle.json")));
if (!replayReport.matches) {
  failures.push("replay bundle did not reproduce the expected verification result");
  failures.push(...replayReport.differences);
}

const receipt = loadJson(path.join(EXAMPLE, "decision_receipt.json")) as any;
if (receipt.decision.result !== replayReport.replayed_result.trust_outcome) {
  failures.push("decision receipt result does not match replayed trust outcome");
}

if (failures.length) {
  console.log("validate_photography_contest_example.ts: FAIL");
  for (const failure of failures) console.log(` - ${failure}`);
  process.exit(1);
}

console.log("validate_photography_contest_example.ts: OK");
console.log(
  JSON.stringify(
    {
      decision: receipt.decision.result,
      replay_matches: replayReport.matches,
      policy_descriptor: policyReport.reason_code,
      revocation_descriptor: revocationReport.reason_code,
    },
    null,
    2,
  ),
);
