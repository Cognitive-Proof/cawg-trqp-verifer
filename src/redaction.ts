import { createHmac } from "node:crypto";

const DEFAULT_KEY = Buffer.from("cawg-trqp-reference-only", "utf-8");

export function keyedDigest(value: string | null | undefined, key: Buffer = DEFAULT_KEY): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  return "hmac-sha256:" + createHmac("sha256", key).update(value, "utf-8").digest("hex");
}

interface RedactOptions {
  includeRaw: boolean;
  includeProcessEvidence: boolean;
  pseudonymize: boolean;
}

export function redactRequest(
  request: Record<string, unknown>,
  { includeRaw, includeProcessEvidence, pseudonymize }: RedactOptions,
): Record<string, unknown> {
  if (includeRaw) {
    const output = { ...request };
    if (!includeProcessEvidence) {
      delete output.process_evidence;
    }
    return output;
  }

  const context = (request.context as Record<string, unknown> | undefined) ?? {};
  const sortedEntries = Object.keys(context)
    .sort()
    .map((key) => [key, context[key]]);

  const output: Record<string, unknown> = {
    asset_id_digest: request.asset_id !== undefined && request.asset_id !== null ? keyedDigest(String(request.asset_id)) : null,
    entity_id_digest:
      request.entity_id !== undefined && request.entity_id !== null ? keyedDigest(String(request.entity_id)) : null,
    authority_id: request.authority_id ?? null,
    issuer_id_digest:
      request.issuer_id !== undefined && request.issuer_id !== null ? keyedDigest(String(request.issuer_id)) : null,
    action: request.action ?? null,
    resource_digest: request.resource !== undefined && request.resource !== null ? keyedDigest(String(request.resource)) : null,
    context_digest: keyedDigest(JSON.stringify(sortedEntries)),
    has_process_evidence: request.process_evidence !== null && request.process_evidence !== undefined,
  };

  if (!pseudonymize) {
    for (const key of ["asset_id", "entity_id", "issuer_id", "resource"]) {
      output[key] = request[key] ?? null;
    }
  }
  return output;
}
