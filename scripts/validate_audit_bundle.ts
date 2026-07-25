import { Command } from "commander";
import { DEFAULT_AUDIT_BUNDLE_SCHEMA, loadJson, validateAuditBundle } from "../src/validation.js";

const program = new Command();
program
  .description("Validate a CAWG-TRQP audit bundle")
  .argument("<bundle_json>", "Path to audit bundle JSON")
  .option("--schema <path>", "Path to audit bundle schema", DEFAULT_AUDIT_BUNDLE_SCHEMA)
  .option("--trust-anchors <path>", "Path to trust anchors JSON for bundle attestation validation")
  .parse(process.argv);

const [bundleJson] = program.args;
const opts = program.opts();

const bundle = loadJson(bundleJson);
const schema = loadJson(opts.schema);
const errors = validateAuditBundle(bundle, schema, { trustAnchorsPath: opts.trustAnchors ?? null });
if (errors.length) {
  console.log(JSON.stringify({ valid: false, errors }, null, 2));
  process.exit(1);
}
console.log(JSON.stringify({ valid: true, bundle_id: bundle.bundle_id ?? null }, null, 2));
