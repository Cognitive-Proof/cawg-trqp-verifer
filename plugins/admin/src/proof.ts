import { createPublicKey, verify } from "node:crypto";
import type { Permission } from "./types.js";

/**
 * The bytes a requester signs to prove control of `entity_id`'s key. Binding
 * the single-use challenge to the exact permission requested means a
 * signature can't be replayed for a different request.
 */
export function accessRequestMessage(challenge: string, entityId: string, permission: Permission): Uint8Array {
  const fields = [challenge, entityId, permission.authority_id, permission.action, permission.resource];
  return new TextEncoder().encode(`trqp-access-request:${JSON.stringify(fields)}`);
}

/** Verifies a signature made with the key that controls `entityId`. */
export interface ProofVerifier {
  /** Whether this verifier can check signatures for `entityId` (e.g. by DID method). */
  supports(entityId: string): boolean;
  verify(entityId: string, message: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Decode(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) {
    const i = BASE58.indexOf(c);
    if (i < 0) throw new Error(`invalid base58 character "${c}"`);
    n = n * 58n + BigInt(i);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const c of s) {
    if (c !== "1") break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

/** The raw 32-byte Ed25519 public key of a `did:key:z6Mk…` identifier (or its verification method URL). */
export function ed25519KeyFromDidKey(didOrVm: string): Uint8Array {
  const did = didOrVm.split("#")[0];
  if (!did.startsWith("did:key:z")) throw new Error(`not a base58btc did:key: ${did}`);
  const bytes = base58Decode(did.slice("did:key:z".length));
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) throw new Error(`not an Ed25519 did:key: ${did}`);
  return bytes.slice(2);
}

// SubjectPublicKeyInfo prefix for Ed25519 (OID 1.3.101.112).
const ED25519_SPKI_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

/** Built-in verifier for `did:key` Ed25519 identifiers. Self-certifying: no network resolution. */
export class DidKeyProofVerifier implements ProofVerifier {
  supports(entityId: string): boolean {
    return entityId.startsWith("did:key:z6Mk");
  }

  async verify(entityId: string, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    try {
      const raw = ed25519KeyFromDidKey(entityId);
      const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
      return verify(null, message, key, signature);
    } catch {
      return false;
    }
  }
}

/** Decodes a base64 or base64url signature. */
export function decodeSignature(signature: string): Uint8Array {
  const normalized = signature.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(Buffer.from(normalized, "base64"));
}
