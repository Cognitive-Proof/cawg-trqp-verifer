import { readFileSync } from "node:fs";
import { createPublicKey, verify } from "node:crypto";
import { canonicalJsonAsciiBytes } from "./jsoncanon.js";

export class SnapshotValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SnapshotValidationError";
  }
}

interface SnapshotStoreOptions {
  verifySignatures?: boolean;
  requireFresh?: boolean;
  currentTime?: Date;
}

export class SnapshotStore {
  readonly data: Record<string, unknown>;
  readonly trustAnchorsPath: string | null;
  readonly verifySignatures: boolean;
  readonly requireFresh: boolean;
  readonly currentTime: Date;
  validationErrors: string[] = [];
  signatureVerified = false;

  constructor(path: string, trustAnchorsPath: string | null = null, options: SnapshotStoreOptions = {}) {
    this.data = JSON.parse(readFileSync(path, "utf-8"));
    this.trustAnchorsPath = trustAnchorsPath;
    this.verifySignatures = options.verifySignatures ?? true;
    this.requireFresh = options.requireFresh ?? true;
    this.currentTime = options.currentTime ?? new Date();

    if (this.verifySignatures) {
      this.verifySignature();
    }
    this.enforceFreshness();
  }

  isUsable(): boolean {
    return this.validationErrors.length === 0;
  }

  status(): string {
    if (this.validationErrors.length) {
      return this.validationErrors[0];
    }
    return this.signatureVerified ? "snapshot_verified" : "snapshot";
  }

  private verifySignature(): void {
    const signatureBlock = this.data.signature as Record<string, unknown> | undefined;
    if (typeof signatureBlock !== "object" || signatureBlock === null || Array.isArray(signatureBlock)) {
      this.validationErrors.push("missing_snapshot_signature");
      return;
    }

    const keyId = signatureBlock.key_id;
    const algorithm = signatureBlock.algorithm;
    const signatureB64 = signatureBlock.value;
    if (algorithm !== "Ed25519" || !keyId || !signatureB64) {
      this.validationErrors.push("invalid_snapshot_signature_metadata");
      return;
    }

    if (this.trustAnchorsPath === null) {
      this.validationErrors.push("missing_trust_anchors");
      return;
    }

    const anchors = JSON.parse(readFileSync(this.trustAnchorsPath, "utf-8"));
    const anchor = (anchors.keys ?? []).find((item: Record<string, unknown>) => item.key_id === keyId);
    if (anchor === undefined) {
      this.validationErrors.push("unknown_snapshot_signer");
      return;
    }

    try {
      const publicKey = createPublicKey({ key: anchor.public_key_pem as string, format: "pem" });
      if (publicKey.asymmetricKeyType !== "ed25519") {
        throw new TypeError("not an Ed25519 public key");
      }
      const payload = SnapshotStore.canonicalPayload(this.data);
      const ok = verify(null, payload, publicKey, Buffer.from(signatureB64 as string, "base64"));
      if (!ok) {
        throw new Error("signature mismatch");
      }
      this.signatureVerified = true;
    } catch {
      this.validationErrors.push("invalid_snapshot_signature");
    }
  }

  private enforceFreshness(): void {
    const expiresAt = this.data.expires_at as string | undefined;
    if (!expiresAt) {
      this.validationErrors.push("missing_snapshot_expiry");
      return;
    }
    let expiry: Date;
    try {
      expiry = SnapshotStore.parseTimestamp(expiresAt);
    } catch {
      this.validationErrors.push("invalid_snapshot_expiry");
      return;
    }

    if (this.requireFresh && this.currentTime.getTime() > expiry.getTime()) {
      this.validationErrors.push("expired_snapshot");
    }
  }

  findAuthorization(
    entityId: string,
    authorityId: string,
    action: string,
    resource: string,
    context: Record<string, unknown>,
  ): Record<string, unknown> | null {
    if (!this.isUsable()) {
      return null;
    }
    const items = (this.data.authorization as Record<string, unknown>[] | undefined) ?? [];
    for (const item of items) {
      if (
        item.entity_id === entityId &&
        item.authority_id === authorityId &&
        item.action === action &&
        item.resource === resource &&
        contextMatches(context, (item.context as Record<string, unknown> | undefined) ?? {})
      ) {
        return item;
      }
    }
    return null;
  }

  findRecognition(
    entityId: string,
    authorityId: string,
    action: string,
    resource: string,
    context: Record<string, unknown>,
  ): Record<string, unknown> | null {
    if (!this.isUsable()) {
      return null;
    }
    const items = (this.data.recognition as Record<string, unknown>[] | undefined) ?? [];
    for (const item of items) {
      if (
        item.entity_id === entityId &&
        item.authority_id === authorityId &&
        item.action === action &&
        item.resource === resource &&
        contextMatches(context, (item.context as Record<string, unknown> | undefined) ?? {})
      ) {
        return item;
      }
    }
    return null;
  }

  static canonicalPayload(data: Record<string, unknown>): Buffer {
    const content = { ...data };
    delete content.signature;
    return canonicalJsonAsciiBytes(content);
  }

  static parseTimestamp(value: string): Date {
    const normalized = value.endsWith("Z") ? value.slice(0, -1) + "+00:00" : value;
    const date = new Date(normalized);
    if (Number.isNaN(date.getTime())) {
      throw new Error(`invalid timestamp: ${value}`);
    }
    return date;
  }
}

function contextMatches(requestContext: Record<string, unknown>, policyContext: Record<string, unknown>): boolean {
  return Object.entries(policyContext).every(([key, value]) => requestContext[key] === value);
}
