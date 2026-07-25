import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { canonicalJsonAsciiBytes } from "./jsoncanon.js";

export class AuditBundleAttestationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuditBundleAttestationError";
  }
}

function canonicalPayload(bundle: Record<string, unknown>): Buffer {
  const content = { ...bundle };
  delete content.bundle_attestation;
  return canonicalJsonAsciiBytes(content);
}

export function signAuditBundle(
  bundle: Record<string, unknown>,
  privateKey: KeyObject,
  { keyId }: { keyId: string },
): Record<string, unknown> {
  const signedBundle = { ...bundle };
  delete signedBundle.bundle_attestation;
  const payload = canonicalPayload(signedBundle);
  const signature = sign(null, payload, privateKey);
  signedBundle.bundle_attestation = {
    algorithm: "Ed25519",
    key_id: keyId,
    value: signature.toString("base64"),
  };
  return signedBundle;
}

export function signAuditBundleFromPath(
  bundle: Record<string, unknown>,
  privateKeyPath: string,
  { keyId }: { keyId: string },
): Record<string, unknown> {
  const privateKey = createPrivateKey({ key: readFileSync(privateKeyPath), format: "pem" });
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new AuditBundleAttestationError("bundle signing key must be an Ed25519 private key");
  }
  return signAuditBundle(bundle, privateKey, { keyId });
}

export function verifyAuditBundleAttestation(bundle: Record<string, unknown>, trustAnchorsPath: string): string[] {
  const attestation = bundle.bundle_attestation as Record<string, unknown> | undefined;
  if (!attestation) {
    return [];
  }

  const keyId = attestation.key_id as string | undefined;
  const algorithm = attestation.algorithm as string | undefined;
  const signatureB64 = attestation.value as string | undefined;
  if (algorithm !== "Ed25519" || !keyId || !signatureB64) {
    return ["attestation: invalid attestation metadata"];
  }

  const anchors = JSON.parse(readFileSync(trustAnchorsPath, "utf-8"));
  const anchor = (anchors.keys ?? []).find((item: Record<string, unknown>) => item.key_id === keyId);
  if (anchor === undefined) {
    return ["attestation: unknown attestation signer"];
  }

  try {
    const publicKey = createPublicKey({ key: anchor.public_key_pem, format: "pem" });
    if (publicKey.asymmetricKeyType !== "ed25519") {
      throw new TypeError("not an Ed25519 public key");
    }
    const ok = verify(null, canonicalPayload(bundle), publicKey, Buffer.from(signatureB64, "base64"));
    if (!ok) {
      return ["attestation: invalid attestation signature"];
    }
  } catch {
    return ["attestation: invalid attestation signature"];
  }
  return [];
}
