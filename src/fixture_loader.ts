import { CAWGManifestParser } from "./manifest_parser.js";
import { createVerificationRequest, type VerificationRequest } from "./models.js";

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

export function loadManifestFixture(path: string, authorityId: string): VerificationRequest {
  const signal = CAWGManifestParser.parseFile(path);
  const raw = signal.raw_manifest;
  const assetId =
    (raw.asset_id as string | undefined) ??
    (asRecord(raw.asset).id as string | undefined) ??
    (asRecord(raw.manifest_store).asset_id as string | undefined) ??
    "asset-unknown";
  const rawIntegrityOk = raw.integrity_ok === undefined ? true : Boolean(raw.integrity_ok);
  const integrityOk = signal.integrity_status !== "failed" && rawIntegrityOk;

  if (!signal.action || !signal.resource) {
    throw new Error("Manifest fixture did not produce action/resource signals");
  }

  return createVerificationRequest({
    asset_id: assetId,
    integrity_ok: Boolean(integrityOk),
    entity_id: signal.actor_id,
    authority_id: authorityId,
    issuer_id: signal.issuer_id,
    action: signal.action,
    resource: signal.resource,
    context: { ...signal.context },
    process_evidence: signal.process_evidence ? { ...signal.process_evidence } : null,
  });
}
