import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { Command } from "commander";

const FIXTURE_ROOT = path.join("fixtures", "profile-bound");
const OUTPUT = path.join("conformance", "assurance-suite-manifest.json");

function loadJson(filePath: string): any {
  return JSON.parse(readFileSync(filePath, "utf-8"));
}

function fixtureEntry(fixtureDir: string): Record<string, unknown> {
  const manifest = loadJson(path.join(fixtureDir, "manifest.json"));
  const assuranceLevel: Record<string, string> = { standard: "AL2", high_assurance: "AL4", edge: "AL2" };
  return {
    fixture_id: manifest.fixture_id,
    profile: manifest.profile,
    assurance_level: assuranceLevel[manifest.profile] ?? "AL1",
    verification_mode: manifest.verification_mode,
    vector_class: "positive",
    implementation_identity: "cawg-trqp-refimpl",
    inputs: manifest.inputs,
    replay_contract: manifest.replay_contract,
    fixture_path: fixtureDir,
  };
}

function buildManifest(): Record<string, unknown> {
  const fixtures = readdirSync(FIXTURE_ROOT)
    .sort()
    .filter((name) => statSync(path.join(FIXTURE_ROOT, name)).isDirectory())
    .map((name) => fixtureEntry(path.join(FIXTURE_ROOT, name)));
  return {
    schema_version: "2026-07-03",
    release: "v0.16.0",
    implementation_identity: {
      id: "cawg-trqp-refimpl",
      role: "reference_implementation",
      authority_scope: "CAWG manifest verification using TRQP-governed trust decisions",
    },
    evidence_artifacts: ["verification_result", "decision_receipt", "audit_bundle", "replay_bundle", "feed_descriptor_evidence"],
    fixtures,
  };
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value), null, 2) + "\n";
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) out[key] = sortKeysDeep(obj[key]);
    return out;
  }
  return value;
}

const program = new Command();
program.description("Export the external assurance-suite manifest").option("--check", "Check that the committed manifest is current").parse(process.argv);
const opts = program.opts();

const manifest = buildManifest();
const content = canonicalJson(manifest);

if (opts.check) {
  const existing = existsSync(OUTPUT) ? readFileSync(OUTPUT, "utf-8") : "";
  if (existing !== content) {
    console.error("conformance/assurance-suite-manifest.json is not current");
    process.exit(1);
  }
  console.log("assurance-suite manifest is current");
} else {
  mkdirSync(path.dirname(OUTPUT), { recursive: true });
  writeFileSync(OUTPUT, content, "utf-8");
  console.log(`wrote ${OUTPUT}`);
}
