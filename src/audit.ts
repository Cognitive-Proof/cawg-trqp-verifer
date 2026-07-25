import { readFileSync } from "node:fs";
import { canonicalJsonBytes, sha256Hex } from "./jsoncanon.js";
import type { VerificationRequest, VerificationResult } from "./models.js";
import { verificationResultToDict } from "./models.js";
import { loadProfile, verificationProfileToDict, type ProfileInput } from "./profile.js";
import { loadPrivacyProfile, type PrivacyProfile } from "./privacy.js";
import { redactRequest } from "./redaction.js";

export const AUDIT_BUNDLE_TYPE = "cawg-trqp-audit-bundle";
export const AUDIT_BUNDLE_PROFILE = "https://sankarshanmukhopadhyay.github.io/cawg-trqp-verifier-refimpl/profiles/audit-bundle/v1";
export const AUDIT_BUNDLE_VERSION = "1.3.0";

export interface AuditBundle {
  bundle_type: string;
  bundle_profile: string;
  bundle_version: string;
  exported_at: string;
  bundle_id: string;
  bundle_digest_sha256: string;
  request_summary: Record<string, unknown>;
  verification_result: Record<string, unknown>;
  policy_evidence: Record<string, unknown>;
  process_appraisal: Record<string, unknown>;
  gateway_mediation: Record<string, unknown>;
  replay_inputs: Record<string, unknown>;
  bundle_attestation: Record<string, unknown>;
}

export function auditBundleToDict(bundle: AuditBundle): Record<string, unknown> {
  const content: Record<string, unknown> = {
    bundle_type: bundle.bundle_type,
    bundle_profile: bundle.bundle_profile,
    bundle_version: bundle.bundle_version,
    exported_at: bundle.exported_at,
    bundle_id: bundle.bundle_id,
    request_summary: bundle.request_summary,
    verification_result: bundle.verification_result,
    policy_evidence: bundle.policy_evidence,
    process_appraisal: bundle.process_appraisal,
    gateway_mediation: bundle.gateway_mediation,
    replay_inputs: bundle.replay_inputs,
  };
  content.bundle_digest_sha256 = sha256Hex(content);
  if (bundle.bundle_attestation && Object.keys(bundle.bundle_attestation).length) {
    content.bundle_attestation = bundle.bundle_attestation;
  }
  return content;
}

export function auditBundleToCanonicalJson(bundle: AuditBundle): Buffer {
  return canonicalJsonBytes(auditBundleToDict(bundle));
}

function requestToSummary(request: VerificationRequest): Record<string, unknown> {
  return {
    asset_id: request.asset_id,
    entity_id: request.entity_id,
    authority_id: request.authority_id,
    issuer_id: request.issuer_id,
    action: request.action,
    resource: request.resource,
    context: request.context,
    has_process_evidence: request.process_evidence !== null,
  };
}

export interface BuildAuditBundleOptions {
  profile?: ProfileInput;
  useGateway?: boolean;
  exportedAt?: string;
  policyPath?: string | null;
  revocationPath?: string | null;
  policyDescriptorPath?: string | null;
  revocationDescriptorPath?: string | null;
  trustAnchorsPath?: string | null;
  privacyProfile?: string | PrivacyProfile | null;
}

export function buildAuditBundle(
  request: VerificationRequest,
  result: VerificationResult,
  options: BuildAuditBundleOptions = {},
): AuditBundle {
  const resolvedProfile = loadProfile(options.profile ?? "standard");
  const resolvedPrivacy = loadPrivacyProfile(options.privacyProfile ?? "replay_bundle");
  const controls = resolvedProfile.controls;
  if (controls.determinism.require_pinned_feeds && (options.policyPath === undefined || options.policyPath === null)) {
    throw new Error("profile requires pinned policy feeds for deterministic replay");
  }

  const exportedAt = options.exportedAt ?? new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const requestSummary = requestToSummary(request);
  const policyFeed: Record<string, unknown> = {};
  if (options.policyPath) {
    policyFeed.policy_source = options.policyPath;
    policyFeed.policy_source_sha256 = sha256Hex(readFileSync(options.policyPath, "utf-8"));
  }
  if (options.revocationPath) {
    policyFeed.revocation_source = options.revocationPath;
    policyFeed.revocation_source_sha256 = sha256Hex(readFileSync(options.revocationPath, "utf-8"));
  }
  if (options.policyDescriptorPath) {
    policyFeed.policy_descriptor_source = options.policyDescriptorPath;
    policyFeed.policy_descriptor_source_sha256 = sha256Hex(readFileSync(options.policyDescriptorPath, "utf-8"));
  }
  if (options.revocationDescriptorPath) {
    policyFeed.revocation_descriptor_source = options.revocationDescriptorPath;
    policyFeed.revocation_descriptor_source_sha256 = sha256Hex(readFileSync(options.revocationDescriptorPath, "utf-8"));
  }
  if (options.trustAnchorsPath) {
    policyFeed.trust_anchors_source = options.trustAnchorsPath;
    policyFeed.trust_anchors_source_sha256 = sha256Hex(readFileSync(options.trustAnchorsPath, "utf-8"));
  }

  const rawRequest: Record<string, unknown> = {
    asset_id: request.asset_id,
    integrity_ok: request.integrity_ok,
    entity_id: request.entity_id,
    authority_id: request.authority_id,
    issuer_id: request.issuer_id,
    action: request.action,
    resource: request.resource,
    context: request.context,
    process_evidence: request.process_evidence,
  };
  const protectedRequest = redactRequest(rawRequest, {
    includeRaw: resolvedPrivacy.include_raw_request,
    includeProcessEvidence: resolvedPrivacy.include_process_evidence,
    pseudonymize: resolvedPrivacy.pseudonymize_identifiers,
  });

  const policyEvidence = result.policy_evidence;
  const transport = (policyEvidence.transport as Record<string, unknown> | undefined) ?? {};
  const revocationStatus = (policyEvidence.revocation_status as Record<string, unknown> | undefined) ?? {};
  const feedDescriptors = (policyEvidence.feed_descriptors as Record<string, unknown> | undefined) ?? {};

  const replayInputs: Record<string, unknown> = {
    request: protectedRequest,
    privacy: {
      profile: resolvedPrivacy.id,
      retention_days: resolvedPrivacy.retention_days,
      access_scope: resolvedPrivacy.access_scope,
      contains_raw_request: resolvedPrivacy.include_raw_request,
    },
    profile: verificationProfileToDict(resolvedProfile),
    use_gateway: options.useGateway ?? false,
    verification_mode: result.verification_mode,
    policy_epoch: policyEvidence.policy_epoch ?? null,
    transport_metadata: transport,
    revocation_status: revocationStatus,
    feed_descriptors: feedDescriptors,
    replay_contract: {
      transport_verified: Boolean(transport.satisfied ?? false),
      revocation_freshness_evaluated: "revocation_status" in policyEvidence,
      feed_descriptor_evidence_available: Boolean(feedDescriptors && Object.keys(feedDescriptors).length),
      deterministic_inputs: Boolean(Object.keys(policyFeed).length),
    },
  };
  if (Object.keys(policyFeed).length) {
    replayInputs.policy_feed = policyFeed;
  }

  const resultDict = verificationResultToDict(result);
  const bundleSeed = {
    request_summary: requestSummary,
    verification_result: resultDict,
    policy_evidence: result.policy_evidence,
    process_appraisal: result.process_appraisal,
    gateway_mediation: result.gateway_mediation,
    replay_inputs: replayInputs,
  };
  const bundleId = `urn:trqp:audit-bundle:sha256:${sha256Hex(bundleSeed)}`;

  const bundle: AuditBundle = {
    bundle_type: AUDIT_BUNDLE_TYPE,
    bundle_profile: AUDIT_BUNDLE_PROFILE,
    bundle_version: AUDIT_BUNDLE_VERSION,
    exported_at: exportedAt,
    bundle_id: bundleId,
    bundle_digest_sha256: "",
    request_summary: requestSummary,
    verification_result: resultDict,
    policy_evidence: result.policy_evidence,
    process_appraisal: result.process_appraisal,
    gateway_mediation: result.gateway_mediation,
    replay_inputs: replayInputs,
    bundle_attestation: {},
  };
  bundle.bundle_digest_sha256 = auditBundleToDict(bundle).bundle_digest_sha256 as string;
  return bundle;
}
