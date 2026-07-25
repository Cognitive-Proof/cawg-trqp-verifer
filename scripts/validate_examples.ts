import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { createAjv } from "../src/ajv.js";

function loadJson(filePath: string): any {
  return JSON.parse(readFileSync(filePath, "utf-8"));
}

function walkJsonFiles(dir: string): string[] {
  const results: string[] = [];
  for (const entry of readdirSync(dir).sort()) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) {
      results.push(...walkJsonFiles(full));
    } else if (entry.endsWith(".json")) {
      results.push(full);
    }
  }
  return results;
}

const SCHEMAS: Record<string, any> = {
  audit_bundle: loadJson("schemas/audit-bundle.schema.json"),
  verification_profile: loadJson("schemas/verification-profile.schema.json"),
  verification_request: loadJson("schemas/verification-request.schema.json"),
  verification_result: loadJson("schemas/verification-result.schema.json"),
  feed_descriptor: loadJson("schemas/feed-descriptor.schema.json"),
};

const ajv = createAjv();
const validators: Record<string, ReturnType<typeof ajv.compile>> = {};
for (const [name, schema] of Object.entries(SCHEMAS)) {
  validators[name] = ajv.compile(schema);
}

interface Target {
  schemaName: string;
  relPath: string;
  data: unknown;
}

function iterValidationTargets(): Target[] {
  const targets: Target[] = [];

  for (const filePath of walkJsonFiles("examples")) {
    const rel = filePath;
    const parts = rel.split(path.sep);
    if (parts[0] === "examples" && parts[1] === "fixtures") continue;
    const data = loadJson(filePath);
    const name = path.basename(filePath);
    if (["exported_audit_bundle.json", "exported_audit_bundle.signed.json", "reproducibility_bundle_standard.json"].includes(name)) {
      targets.push({ schemaName: "audit_bundle", relPath: rel, data });
    } else if (path.basename(path.dirname(filePath)) === "expected") {
      targets.push({ schemaName: "verification_result", relPath: rel, data });
    } else if (name.startsWith("benchmark_") || ["verification_request.json", "interoperability_vector_gateway.json"].includes(name)) {
      targets.push({ schemaName: "verification_request", relPath: rel, data });
    } else if (name === "interoperability_vector_multi_authority.json") {
      const vectors = (data as any).vectors ?? [];
      vectors.forEach((item: unknown, idx: number) => {
        targets.push({ schemaName: "verification_request", relPath: `${rel}:vectors[${idx}]`, data: item });
      });
    }
  }

  const feedDescriptorDir = "examples/feed_descriptors";
  for (const filePath of readdirSync(feedDescriptorDir).sort()) {
    if (!filePath.endsWith(".json")) continue;
    const full = path.join(feedDescriptorDir, filePath);
    targets.push({ schemaName: "feed_descriptor", relPath: full, data: loadJson(full) });
  }

  const profileBoundDir = "fixtures/profile-bound";
  for (const fixtureName of readdirSync(profileBoundDir).sort()) {
    const base = path.join(profileBoundDir, fixtureName);
    if (!statSync(base).isDirectory()) continue;
    const requestPath = path.join(base, "request.json");
    const resolvedProfilePath = path.join(base, "resolved_profile.json");
    const expectedResultPath = path.join(base, "expected_result.json");
    if (existsFile(requestPath)) targets.push({ schemaName: "verification_request", relPath: requestPath, data: loadJson(requestPath) });
    if (existsFile(resolvedProfilePath)) targets.push({ schemaName: "verification_profile", relPath: resolvedProfilePath, data: loadJson(resolvedProfilePath) });
    if (existsFile(expectedResultPath)) targets.push({ schemaName: "verification_result", relPath: expectedResultPath, data: loadJson(expectedResultPath) });
  }

  return targets;
}

function existsFile(filePath: string): boolean {
  try {
    return statSync(filePath).isFile();
  } catch {
    return false;
  }
}

const failures: string[] = [];
let checked = 0;
for (const { schemaName, relPath, data } of iterValidationTargets()) {
  const validate = validators[schemaName];
  if (!validate(data)) {
    for (const err of validate.errors ?? []) {
      const pointer = err.instancePath.replace(/^\//, "") || "<root>";
      failures.push(`${relPath}: ${pointer}: ${err.message}`);
    }
  }
  checked += 1;
}

if (failures.length) {
  console.log("validate_examples.ts: FAIL");
  for (const failure of failures) console.log(` - ${failure}`);
  process.exit(1);
}
console.log(`validate_examples.ts: ${checked}/${checked} OK`);
