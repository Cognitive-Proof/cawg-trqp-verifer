import { createHash } from "node:crypto";
import { canonicalJsonAsciiText } from "./jsoncanon.js";

export function normalizeContext(context: Record<string, unknown>): Record<string, unknown> {
  const sortedKeys = Object.keys(context).sort();
  const result: Record<string, unknown> = {};
  for (const key of sortedKeys) {
    result[key] = context[key];
  }
  return result;
}

export function contextHash(context: Record<string, unknown>): string {
  const normalized = normalizeContext(context);
  const payload = canonicalJsonAsciiText(normalized);
  return createHash("sha256").update(Buffer.from(payload, "utf-8")).digest("hex");
}

export function tupleKey(
  entityId: string,
  authorityId: string,
  action: string,
  resource: string,
  context: Record<string, unknown>,
): string {
  return [entityId, authorityId, action, resource, contextHash(context)].join("|");
}
