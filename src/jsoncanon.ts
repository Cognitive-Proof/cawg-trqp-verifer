import { createHash } from "node:crypto";

/**
 * Mirrors Python's json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False):
 * recursively sort object keys, compact separators, non-ASCII left unescaped.
 * This must stay byte-compatible with the Python reference implementation because
 * digests/signatures computed here (bundle_digest_sha256, descriptor_signature, ...)
 * are verified against artifacts produced by the Python implementation.
 */
function canonicalizeValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalizeValue);
  }
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const sortedKeys = Object.keys(obj).sort();
    const result: Record<string, unknown> = {};
    for (const key of sortedKeys) {
      result[key] = canonicalizeValue(obj[key]);
    }
    return result;
  }
  return value;
}

export function canonicalJsonText(value: unknown): string {
  return JSON.stringify(canonicalizeValue(value));
}

export function canonicalJsonBytes(value: unknown): Buffer {
  return Buffer.from(canonicalJsonText(value), "utf-8");
}

export function sha256Hex(value: unknown): string {
  return createHash("sha256").update(canonicalJsonBytes(value)).digest("hex");
}

const NON_ASCII_THRESHOLD = 0x80;

/**
 * Mirrors Python's json.dumps(value, sort_keys=True, separators=(",", ":")) with the
 * ensure_ascii default (True): any UTF-16 code unit >= 0x80 is escaped as \\uXXXX
 * (surrogate halves escaped individually, matching how Python escapes astral characters).
 * Several signing payloads (bundle attestation, feed descriptors, snapshots) use this
 * form rather than the ensure_ascii=False form above - both must be replicated exactly.
 */
function escapeNonAscii(text: string): string {
  let out = "";
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code < NON_ASCII_THRESHOLD) {
      out += text[i];
    } else {
      out += String.fromCharCode(92, 117) + code.toString(16).padStart(4, "0");
    }
  }
  return out;
}

export function canonicalJsonAsciiText(value: unknown): string {
  return escapeNonAscii(JSON.stringify(canonicalizeValue(value)));
}

export function canonicalJsonAsciiBytes(value: unknown): Buffer {
  return Buffer.from(canonicalJsonAsciiText(value), "utf-8");
}
