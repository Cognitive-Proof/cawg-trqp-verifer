import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { createAjv } from "../src/ajv.js";
import { validateFeedDescriptor } from "../src/feed_descriptor.js";

const SCHEMA = JSON.parse(readFileSync("schemas/feed-descriptor.schema.json", "utf-8"));
const TRUST = JSON.parse(readFileSync("data/trust_anchors.json", "utf-8"));
const EXPECTED = new Set(["did:web:media-registry.example"]);

const validate = createAjv().compile(SCHEMA);

const failures: string[] = [];
const dir = "examples/feed_descriptors";
for (const file of readdirSync(dir).sort()) {
  if (!file.endsWith(".json")) continue;
  const filePath = path.join(dir, file);
  const descriptor = JSON.parse(readFileSync(filePath, "utf-8"));
  if (!validate(descriptor)) {
    for (const err of validate.errors ?? []) {
      failures.push(`${filePath} schema: ${err.instancePath.replace(/^\//, "") || "<root>"}: ${err.message}`);
    }
  }
  const source = descriptor.feed.source;
  const report = validateFeedDescriptor(descriptor, readFileSync(source, "utf-8"), {
    trustAnchors: TRUST,
    expectedAuthorities: EXPECTED,
  });
  if (report.reason_code !== "fresh") {
    failures.push(`${filePath} validation: ${report.reason_code} ${JSON.stringify(report.violations)}`);
  }
}

if (failures.length) {
  console.log("validate_feed_descriptors.ts: FAIL");
  for (const item of failures) console.log(` - ${item}`);
  process.exit(1);
}
console.log("validate_feed_descriptors.ts: all feed descriptors OK");
