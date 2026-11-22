import { generateKeyPairSync, sign } from "node:crypto";
import { accessRequestMessage } from "../proof.js";
import type { Permission } from "../types.js";

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) {
    out = BASE58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out;
}

/** A fresh Ed25519 did:key identity that can sign access requests. */
export function didKeyIdentity() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x as string, "base64url");
  const did = `did:key:z${base58(Uint8Array.from([0xed, 0x01, ...raw]))}`;
  return {
    did,
    signRequest(challenge: string, permission: Permission, entityId = did): string {
      return sign(null, accessRequestMessage(challenge, entityId, permission), privateKey).toString("base64");
    },
  };
}

export const ISSUE: Permission = {
  authority_id: "did:web:registry.example",
  action: "issue",
  resource: "ExampleGuildLikenessConsentCredential",
};

export const PUBLISH_STATUS: Permission = { ...ISSUE, action: "publish-status" };

/** A controllable clock. */
export function clock(start = "2026-11-21T12:00:00Z") {
  let t = new Date(start).getTime();
  return {
    now: () => new Date(t),
    advance(seconds: number) {
      t += seconds * 1000;
    },
    iso: () => new Date(t).toISOString(),
  };
}
