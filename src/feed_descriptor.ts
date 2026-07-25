import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { canonicalJsonAsciiBytes } from "./jsoncanon.js";

export class FeedDescriptorError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FeedDescriptorError";
  }
}

export const FRESHNESS_REASON_CODES = new Set([
  "fresh",
  "stale_but_warned",
  "stale_rejected",
  "missing_feed_descriptor",
  "descriptor_signature_invalid",
  "descriptor_digest_mismatch",
  "authority_not_recognized",
  "route_unattested",
  "revocation_channel_degraded",
  "descriptor_malformed",
]);

function parseUtc(ts: string | null | undefined): Date | null {
  if (!ts) return null;
  const date = new Date(ts);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function canonicalDescriptorPayload(descriptor: Record<string, unknown>): Buffer {
  const content = { ...descriptor };
  delete content.descriptor_signature;
  return canonicalJsonAsciiBytes(content);
}

export function signFeedDescriptor(
  descriptor: Record<string, unknown>,
  privateKey: KeyObject,
  { keyId }: { keyId: string },
): Record<string, unknown> {
  const signed = { ...descriptor };
  delete signed.descriptor_signature;
  const signature = sign(null, canonicalDescriptorPayload(signed), privateKey);
  signed.descriptor_signature = {
    algorithm: "Ed25519",
    key_id: keyId,
    value: signature.toString("base64"),
  };
  return signed;
}

export function signFeedDescriptorFromPath(
  descriptor: Record<string, unknown>,
  privateKeyPath: string,
  { keyId }: { keyId: string },
): Record<string, unknown> {
  const privateKey = createPrivateKey({ key: readFileSync(privateKeyPath), format: "pem" });
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new FeedDescriptorError("feed descriptor signing key must be an Ed25519 private key");
  }
  return signFeedDescriptor(descriptor, privateKey, { keyId });
}

export function loadTrustAnchor(
  trustAnchors: Record<string, unknown>,
  keyId: string,
): Record<string, unknown> | undefined {
  const keys = (trustAnchors.keys as Record<string, unknown>[] | undefined) ?? [];
  return keys.find((item) => item.key_id === keyId);
}

export function validateFeedDescriptorSignature(
  descriptor: Record<string, unknown>,
  trustAnchors: Record<string, unknown>,
): [boolean, string | null] {
  const signature = descriptor.descriptor_signature as Record<string, unknown> | undefined;
  if (!signature) {
    return [false, "missing descriptor signature"];
  }
  if (signature.algorithm !== "Ed25519" || !signature.key_id || !signature.value) {
    return [false, "invalid descriptor signature metadata"];
  }
  const anchor = loadTrustAnchor(trustAnchors, signature.key_id as string);
  if (anchor === undefined) {
    return [false, "descriptor signer is not recognized by configured trust anchors"];
  }
  try {
    const publicKey = createPublicKey({ key: anchor.public_key_pem as string, format: "pem" });
    if (publicKey.asymmetricKeyType !== "ed25519") {
      throw new TypeError("not an Ed25519 public key");
    }
    const rawSignature = Buffer.from(signature.value as string, "base64");
    if (rawSignature.length !== 64) {
      return [false, "descriptor signature verification failed"];
    }
    const ok = verify(null, canonicalDescriptorPayload(descriptor), publicKey, rawSignature);
    if (!ok) {
      return [false, "descriptor signature verification failed"];
    }
  } catch {
    return [false, "descriptor signature verification failed"];
  }
  return [true, null];
}

export interface FeedValidationReport {
  descriptor_id: string | null;
  feed_type: string | null;
  authority_id: string | null;
  route_attested: boolean;
  integrity_ok: boolean;
  authority_ok: boolean;
  signature_ok: boolean;
  freshness_ok: boolean;
  reason_code: string;
  violations: string[];
  digest_sha256: string | null;
  declared_digest_sha256: string | null;
  issued_at: string | null;
  valid_until: string | null;
  max_age_seconds: number | null;
}

function report(fields: Partial<FeedValidationReport> & Pick<FeedValidationReport, "reason_code">): FeedValidationReport {
  return {
    descriptor_id: null,
    feed_type: null,
    authority_id: null,
    route_attested: false,
    integrity_ok: false,
    authority_ok: false,
    signature_ok: false,
    freshness_ok: false,
    violations: [],
    digest_sha256: null,
    declared_digest_sha256: null,
    issued_at: null,
    valid_until: null,
    max_age_seconds: null,
    ...fields,
  };
}

export function validateFeedDescriptor(
  descriptor: Record<string, unknown> | null | undefined,
  feedBody: string | Buffer | Record<string, unknown> | unknown[] | null | undefined,
  {
    trustAnchors,
    expectedAuthorities,
    routeRequired = false,
    now,
  }: {
    trustAnchors: Record<string, unknown> | null | undefined;
    expectedAuthorities?: Set<string> | null;
    routeRequired?: boolean;
    now?: Date;
  },
): FeedValidationReport {
  const evalTime = now ?? new Date();
  if (descriptor === null || descriptor === undefined) {
    return report({
      reason_code: "missing_feed_descriptor",
      violations: ["feed descriptor is missing"],
    });
  }
  if (typeof descriptor !== "object" || Array.isArray(descriptor)) {
    return report({
      reason_code: "descriptor_malformed",
      violations: ["feed descriptor must be a JSON object"],
    });
  }

  const violations: string[] = [];
  let bodyBytes: Buffer;
  if (Buffer.isBuffer(feedBody)) {
    bodyBytes = feedBody;
  } else if (typeof feedBody === "string") {
    bodyBytes = Buffer.from(feedBody, "utf-8");
  } else if (feedBody === null || feedBody === undefined) {
    bodyBytes = Buffer.alloc(0);
  } else {
    bodyBytes = canonicalJsonAsciiBytes(feedBody);
  }

  const actualDigest = createHash("sha256").update(bodyBytes).digest("hex");
  let feed = (descriptor.feed as Record<string, unknown> | undefined) ?? {};
  if (typeof feed !== "object" || Array.isArray(feed)) {
    feed = {};
    violations.push("feed descriptor feed section is malformed");
  }
  const declaredDigest = feed.digest_sha256 as string | undefined;
  const integrityOk = Boolean(declaredDigest && actualDigest === declaredDigest);
  if (!integrityOk) {
    violations.push("feed descriptor digest does not match feed body");
  }

  let signatureOk = false;
  if (trustAnchors === null || trustAnchors === undefined) {
    violations.push("trust anchors unavailable for feed descriptor validation");
  } else {
    const [ok, signatureError] = validateFeedDescriptorSignature(descriptor, trustAnchors);
    signatureOk = ok;
    if (!ok && signatureError) {
      violations.push(signatureError);
    }
  }

  let authority = (descriptor.authority as Record<string, unknown> | undefined) ?? {};
  if (typeof authority !== "object" || Array.isArray(authority)) {
    authority = {};
    violations.push("feed descriptor authority section is malformed");
  }
  const authorityId = authority.authority_id as string | undefined;
  const authorityOk = Boolean(authorityId) && (!expectedAuthorities || expectedAuthorities.has(authorityId as string));
  if (!authorityOk) {
    violations.push(`feed authority '${authorityId}' is not recognized for this verification scope`);
  }

  let route = (descriptor.route as Record<string, unknown> | undefined) ?? {};
  if (typeof route !== "object" || Array.isArray(route)) {
    route = {};
    violations.push("feed descriptor route section is malformed");
  }
  const routeAttested = Boolean(route.attested ?? false);
  if (routeRequired && !routeAttested) {
    violations.push("feed route is not attested");
  }

  const validUntilRaw = descriptor.valid_until as string | undefined;
  const validUntil = parseUtc(validUntilRaw);
  let freshnessOk = true;
  if (validUntilRaw && validUntil === null) {
    freshnessOk = false;
    violations.push("feed descriptor validity timestamp is malformed");
  }
  if (validUntil !== null && evalTime.getTime() > validUntil.getTime()) {
    freshnessOk = false;
    violations.push("feed descriptor validity window has expired");
  }

  let reason: string;
  if (violations.some((item) => item.includes("malformed"))) {
    reason = "descriptor_malformed";
  } else if (!signatureOk) {
    reason = "descriptor_signature_invalid";
  } else if (!integrityOk) {
    reason = "descriptor_digest_mismatch";
  } else if (!authorityOk) {
    reason = "authority_not_recognized";
  } else if (routeRequired && !routeAttested) {
    reason = "route_unattested";
  } else if (!freshnessOk) {
    reason = "stale_rejected";
  } else {
    reason = "fresh";
  }

  const freshness = descriptor.freshness as Record<string, unknown> | undefined;

  return report({
    descriptor_id: (descriptor.descriptor_id as string | undefined) ?? null,
    feed_type: (feed.feed_type as string | undefined) ?? null,
    authority_id: authorityId ?? null,
    route_attested: routeAttested,
    integrity_ok: integrityOk,
    authority_ok: authorityOk,
    signature_ok: signatureOk,
    freshness_ok: freshnessOk,
    reason_code: reason,
    violations,
    digest_sha256: actualDigest,
    declared_digest_sha256: declaredDigest ?? null,
    issued_at: (descriptor.issued_at as string | undefined) ?? null,
    valid_until: validUntilRaw ?? null,
    max_age_seconds:
      freshness && typeof freshness === "object" && !Array.isArray(freshness)
        ? ((freshness.max_age_seconds as number | undefined) ?? null)
        : null,
  });
}

export function loadFeedDescriptor(path: string | null | undefined): Record<string, unknown> | null {
  if (!path) {
    return null;
  }
  return JSON.parse(readFileSync(path, "utf-8"));
}
