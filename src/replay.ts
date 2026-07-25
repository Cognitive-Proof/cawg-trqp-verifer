import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { canonicalJsonText, sha256Hex } from "./jsoncanon.js";

/**
 * Order-independent structural equality, matching Python's dict `!=` comparison
 * semantics (JSON objects are unordered; raw JSON.stringify comparison is not).
 */
function deepEqual(a: unknown, b: unknown): boolean {
  return canonicalJsonText(a) === canonicalJsonText(b);
}
import { TrustGateway } from "./gateway.js";
import { createVerificationRequest, type VerificationRequest } from "./models.js";
import { MockTRQPService } from "./mock_service.js";
import { loadProfile, type ProfileInput } from "./profile.js";
import { Verifier } from "./verifier.js";

export interface ReplayReport {
  replayed_result: Record<string, unknown>;
  expected_result: Record<string, unknown>;
  matches: boolean;
  differences: string[];
  policy_sources: Record<string, string>;
}

const COMPARE_FIELDS = [
  "asset_integrity",
  "assertion_binding",
  "issuer_recognition",
  "actor_authorization",
  "process_integrity",
  "policy_freshness",
  "verification_mode",
  "trust_outcome",
] as const;

export interface ReplayOptions {
  policyPath?: string | null;
  revocationPath?: string | null;
  trustedRoot?: string;
}

export function replayAuditBundle(bundle: Record<string, unknown>, options: ReplayOptions = {}): ReplayReport {
  const inputs = (bundle.replay_inputs as Record<string, unknown> | undefined) ?? {};
  const request = createVerificationRequest(inputs.request as VerificationRequest);
  const profileRef = (inputs.profile as ProfileInput | undefined) ?? "standard";
  const resolvedProfile = loadProfile(profileRef);
  const useGateway = Boolean(inputs.use_gateway ?? false);
  const policyFeed = (inputs.policy_feed as Record<string, unknown> | undefined) ?? {};
  const root = path.resolve(options.trustedRoot ?? ".");

  const resolvedPolicyPath = verifiedBundlePath(
    options.policyPath ?? (policyFeed.policy_source as string | undefined),
    options.policyPath === undefined ? (policyFeed.policy_source_sha256 as string | undefined) : undefined,
    root,
    "policy_source",
    true,
  );
  const resolvedRevocationPath = verifiedBundlePath(
    options.revocationPath ?? (policyFeed.revocation_source as string | undefined),
    options.revocationPath === undefined ? (policyFeed.revocation_source_sha256 as string | undefined) : undefined,
    root,
    "revocation_source",
    false,
  );
  const policyDescriptorPath = verifiedBundlePath(
    policyFeed.policy_descriptor_source as string | undefined,
    policyFeed.policy_descriptor_source_sha256 as string | undefined,
    root,
    "policy_descriptor_source",
    false,
  );
  const revocationDescriptorPath = verifiedBundlePath(
    policyFeed.revocation_descriptor_source as string | undefined,
    policyFeed.revocation_descriptor_source_sha256 as string | undefined,
    root,
    "revocation_descriptor_source",
    false,
  );
  const trustAnchorsPath = verifiedBundlePath(
    (policyFeed.trust_anchors_source as string | undefined) ?? "data/trust_anchors.json",
    policyFeed.trust_anchors_source_sha256 as string | undefined,
    root,
    "trust_anchors_source",
    false,
  );

  if (resolvedProfile.base_profile !== "edge" && !resolvedPolicyPath) {
    throw new Error("policy_path is required unless replay_inputs.policy_feed.policy_source is present");
  }

  let service: MockTRQPService | null;
  let gateway: TrustGateway | null;
  if (useGateway) {
    service = new MockTRQPService(resolvedPolicyPath as string, resolvedRevocationPath, {
      transportMode: "http",
      transportIntegrity: "tls",
      policyDescriptorPath,
      revocationDescriptorPath,
      trustAnchorsPath,
    });
    gateway = new TrustGateway(service);
  } else {
    service =
      resolvedProfile.base_profile === "edge"
        ? null
        : new MockTRQPService(resolvedPolicyPath as string, resolvedRevocationPath, {
            policyDescriptorPath,
            revocationDescriptorPath,
            trustAnchorsPath,
          });
    gateway = null;
  }
  const verifier = new Verifier({ service: service ?? undefined, gateway: gateway ?? undefined });
  const result = verifier.verify(request, resolvedProfile);
  const resultDict = result as unknown as Record<string, unknown>;
  const expected = (bundle.verification_result as Record<string, unknown> | undefined) ?? {};

  const differences: string[] = [];
  for (const field of COMPARE_FIELDS) {
    if (resultDict[field] !== expected[field]) {
      differences.push(`${field}: expected=${JSON.stringify(expected[field])} actual=${JSON.stringify(resultDict[field])}`);
    }
  }

  const policyEvidence = (resultDict.policy_evidence as Record<string, unknown> | undefined) ?? {};
  const expectedEpoch = inputs.policy_epoch;
  const actualEpoch = policyEvidence.policy_epoch;
  if (expectedEpoch !== actualEpoch) {
    differences.push(`policy_epoch: expected=${JSON.stringify(expectedEpoch)} actual=${JSON.stringify(actualEpoch)}`);
  }

  const expectedProfile = inputs.profile;
  const actualProfile = policyEvidence.verification_profile;
  if (
    expectedProfile !== null &&
    typeof expectedProfile === "object" &&
    !deepEqual(actualProfile, expectedProfile)
  ) {
    differences.push(
      "verification_profile: expected bundle replay_inputs.profile to match replayed policy_evidence.verification_profile",
    );
  }

  const expectedTransport = inputs.transport_metadata;
  const actualTransport = policyEvidence.transport;
  if (expectedTransport && !deepEqual(actualTransport, expectedTransport)) {
    differences.push(
      "transport_metadata: expected replay_inputs.transport_metadata to match replayed policy_evidence.transport",
    );
  }

  const expectedRevocation = inputs.revocation_status;
  const actualRevocation = policyEvidence.revocation_status;
  if (expectedRevocation && !deepEqual(actualRevocation, expectedRevocation)) {
    differences.push(
      "revocation_status: expected replay_inputs.revocation_status to match replayed policy_evidence.revocation_status",
    );
  }

  return {
    replayed_result: resultDict,
    expected_result: expected,
    matches: differences.length === 0,
    differences,
    policy_sources: {
      policy_source: displayReplayPath(resolvedPolicyPath, root),
      revocation_source: displayReplayPath(resolvedRevocationPath, root),
    },
  };
}

function verifiedBundlePath(
  pathValue: string | undefined,
  expectedDigest: string | undefined,
  trustedRoot: string,
  label: string,
  required: boolean,
): string | null {
  if (!pathValue) {
    if (required) {
      throw new Error(`${label} is required for replay`);
    }
    return null;
  }
  const resolved = path.isAbsolute(pathValue) ? path.resolve(pathValue) : path.resolve(trustedRoot, pathValue);
  const relative = path.relative(trustedRoot, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`${label} must resolve under trusted replay root ${trustedRoot}`);
  }
  if (!existsSync(resolved)) {
    if (required) {
      throw new Error(`${label} does not exist: ${pathValue}`);
    }
    return null;
  }
  if (expectedDigest) {
    const actual = sha256Hex(readFileSync(resolved, "utf-8"));
    if (actual !== expectedDigest) {
      throw new Error(`${label} digest mismatch`);
    }
  }
  return resolved;
}

function displayReplayPath(pathValue: string | null, trustedRoot: string): string {
  if (!pathValue) {
    return "";
  }
  const resolved = path.resolve(pathValue);
  const relative = path.relative(trustedRoot, resolved);
  return relative.startsWith("..") ? resolved : relative;
}
