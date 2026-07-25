import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createAjv } from "./ajv.js";
import { verifyAuditBundleAttestation } from "./attestation.js";
import { sha256Hex } from "./jsoncanon.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = path.resolve(__dirname, "..");

export class BundleValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BundleValidationError";
  }
}

export const DEFAULT_AUDIT_BUNDLE_SCHEMA = path.join(PACKAGE_ROOT, "schemas", "audit-bundle.schema.json");

export function loadJson(filePath: string): Record<string, unknown> {
  return JSON.parse(readFileSync(filePath, "utf-8"));
}

export function validateAuditBundle(
  bundle: Record<string, unknown>,
  schema: Record<string, unknown>,
  { trustAnchorsPath }: { trustAnchorsPath?: string | null } = {},
): string[] {
  const validate = createAjv().compile(schema);
  const valid = validate(bundle);
  const messages: string[] = [];
  if (!valid) {
    const errors = [...(validate.errors ?? [])].sort((a, b) => (a.instancePath ?? "").localeCompare(b.instancePath ?? ""));
    for (const err of errors) {
      messages.push(`schema: ${err.instancePath.replace(/^\//, "") || "<root>"}: ${err.message}`);
    }
  }

  const expectedDigest = bundle.bundle_digest_sha256 as string | undefined;
  if (expectedDigest) {
    const content = { ...bundle };
    delete content.bundle_digest_sha256;
    delete content.bundle_attestation;
    const actualDigest = sha256Hex(content);
    if (actualDigest !== expectedDigest) {
      messages.push("determinism: bundle_digest_sha256 does not match canonical bundle content");
    }
  }

  const bundleId = (bundle.bundle_id as string | undefined) ?? "";
  if (bundleId && !bundleId.startsWith("urn:trqp:audit-bundle:sha256:")) {
    messages.push("determinism: bundle_id must use urn:trqp:audit-bundle:sha256:<digest> format");
  }

  if (bundle.bundle_attestation && Object.keys(bundle.bundle_attestation as Record<string, unknown>).length) {
    if (!trustAnchorsPath) {
      messages.push("attestation: trust anchors are required to validate bundle_attestation");
    } else {
      messages.push(...verifyAuditBundleAttestation(bundle, trustAnchorsPath));
    }
  }

  return messages;
}
