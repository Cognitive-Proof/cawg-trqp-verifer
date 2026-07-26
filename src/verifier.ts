import { TTLCache, type DecisionCache } from "./DecisionCache/index.js";
import { tupleKey } from "./context.js";
import {
  createVerificationResult,
  type VerificationRequest,
  type VerificationResult,
} from "./models.js";
import type { PolicyService } from "./policy_service.js";
import { SnapshotStore } from "./snapshot.js";
import { TrustGateway } from "./gateway.js";
import { loadProfile, verificationProfileToDict, type ProfileInput, type VerificationProfile } from "./profile.js";
import {
  createFeedTransportMetadata,
  evaluateTransportConstraints,
  feedTransportMetadataToDict,
  type FeedTransportMetadata,
} from "./transport.js";

/** Model for revocation delta updates. */
export class RevocationDelta {
  readonly revokedEntities: Set<string>;
  readonly policyEpoch: string | null;
  readonly timestamp: string;

  constructor(revokedEntities: string[], policyEpoch: string | null = null) {
    this.revokedEntities = new Set(revokedEntities);
    this.policyEpoch = policyEpoch;
    this.timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  }

  apply(entityId: string): [boolean, string | null] {
    if (this.revokedEntities.has(entityId)) {
      return [true, `revoked_in_epoch_${this.policyEpoch ?? "unknown"}`];
    }
    return [false, null];
  }
}

export interface VerifierOptions {
  service?: PolicyService | null;
  snapshot?: SnapshotStore | null;
  cache?: DecisionCache<Record<string, unknown>> | null;
  gateway?: TrustGateway | null;
}

export class Verifier {
  service: PolicyService | null;
  snapshot: SnapshotStore | null;
  cache: DecisionCache<Record<string, unknown>>;
  gateway: TrustGateway | null;
  revocationDelta: RevocationDelta | null = null;
  lastTransportMetadata: Record<string, unknown> = {};
  lastRevocationStatus: Record<string, unknown> = {};
  lastFeedDescriptorEvidence: Record<string, unknown> = {};

  constructor(options: VerifierOptions = {}) {
    this.service = options.service ?? null;
    this.snapshot = options.snapshot ?? null;
    this.cache = options.cache ?? new TTLCache<Record<string, unknown>>();
    this.gateway = options.gateway ?? null;
  }

  applyRevocationDelta(revokedEntities: string[], policyEpoch: string | null = null): void {
    this.revocationDelta = new RevocationDelta(revokedEntities, policyEpoch);
  }

  async verify(request: VerificationRequest, profile: ProfileInput = "standard"): Promise<VerificationResult> {
    const resolvedProfile = loadProfile(profile);
    if (!request.integrity_ok) {
      return createVerificationResult({
        asset_integrity: "failed",
        assertion_binding: "unknown",
        issuer_recognition: "unknown",
        actor_authorization: "unknown",
        process_integrity: "unknown",
        policy_freshness: "n/a",
        verification_mode: "local_only",
        trust_outcome: "rejected",
        explanations: [`Asset integrity verification failed under profile ${resolvedProfile.id}`],
      });
    }

    if (this.revocationDelta !== null) {
      const [isRevoked, reason] = this.revocationDelta.apply(request.entity_id);
      if (isRevoked) {
        this.lastRevocationStatus = {
          status: "revoked",
          source: "delta_cache",
          policy_epoch: this.revocationDelta.policyEpoch,
          freshness_ok: true,
        };
        return createVerificationResult({
          asset_integrity: "verified",
          assertion_binding: "verified",
          issuer_recognition: "unknown",
          actor_authorization: "not_authorized",
          process_integrity: "not_evaluated",
          policy_freshness: "revoked",
          verification_mode: "revocation_check",
          trust_outcome: "rejected",
          explanations: [`Entity revoked: ${reason}`, `Verification profile: ${resolvedProfile.id}`],
          policy_evidence: {
            verification_profile: verificationProfileToDict(resolvedProfile),
            revocation_status: this.lastRevocationStatus,
            feed_descriptors: this.lastFeedDescriptorEvidence,
          },
        });
      }
    }

    const authKey = tupleKey(request.entity_id, request.authority_id, request.action, request.resource, request.context);
    const recContext: Record<string, unknown> = {};
    if ("credential_type" in request.context) {
      recContext.credential_type = request.context.credential_type;
    }
    const recKey = tupleKey(request.authority_id, request.issuer_id ?? "", "recognition", "issuer", recContext);

    if (resolvedProfile.base_profile === "edge") {
      return this.verifyEdge(request, recContext, resolvedProfile);
    }

    const forceLive = Boolean(resolvedProfile.controls.freshness.require_live);
    return this.verifyOnline(request, authKey, recKey, recContext, forceLive, resolvedProfile);
  }

  private currentTransportMetadata(): FeedTransportMetadata {
    if (this.gateway !== null) {
      return this.gateway.transportMetadata;
    }
    if (this.service !== null) {
      return this.service.transportMetadata;
    }
    return createFeedTransportMetadata({ mode: "local", integrity: "none", available: false, channel: "none" });
  }

  private async currentFeedDescriptorEvidence(): Promise<Record<string, unknown>> {
    if (this.gateway !== null && this.gateway.service !== null) {
      return this.gateway.service.feedDescriptorEvidence();
    }
    if (this.service !== null) {
      return this.service.feedDescriptorEvidence();
    }
    return {};
  }

  private async currentRevocationStatus(profile: VerificationProfile): Promise<Record<string, unknown>> {
    const maxAge = (profile.controls.revocation.max_age_seconds as number | undefined) ?? 0;
    const enforcement = (profile.controls.revocation.enforcement as string | undefined) ?? "warn";
    const failures: string[] = [];
    let status: Record<string, unknown>;
    if (this.service !== null) {
      status = { source: "service", ...(await this.service.revocationStatus()) };
    } else {
      status = { source: "none", channel: "none", age_seconds: null };
    }

    const ageSeconds = status.age_seconds as number | null | undefined;
    if (ageSeconds !== null && ageSeconds !== undefined && ageSeconds > maxAge) {
      failures.push(`revocation data age ${ageSeconds}s exceeds allowed window ${maxAge}s`);
    }
    if (profile.controls.revocation.delta_channel_required && !["delta", "live", "mediated"].includes(status.channel as string)) {
      failures.push(`revocation channel '${status.channel}' does not satisfy required delta/live semantics`);
    }

    status.freshness_ok = failures.length === 0;
    status.max_age_seconds = maxAge;
    status.enforcement = enforcement;
    status.violations = failures;
    return status;
  }

  private evaluateTransport(profile: VerificationProfile): [boolean, string[]] {
    const actual = this.currentTransportMetadata();
    const failures = evaluateTransportConstraints(profile.controls.transport, actual);
    this.lastTransportMetadata = {
      required: { ...profile.controls.transport },
      actual: feedTransportMetadataToDict(actual),
      violations: [...failures],
      satisfied: failures.length === 0,
    };
    return [failures.length === 0, failures];
  }

  private async evaluateRevocationFreshness(profile: VerificationProfile): Promise<[boolean, string[]]> {
    const status = await this.currentRevocationStatus(profile);
    this.lastRevocationStatus = status;
    const failures = [...((status.violations as string[] | undefined) ?? [])];
    this.lastFeedDescriptorEvidence = await this.currentFeedDescriptorEvidence();
    const descriptorPolicy = (profile.controls.descriptor_policy as Record<string, string> | undefined) ?? {};
    const descriptorFailureReasons = new Set([
      "descriptor_malformed",
      "descriptor_signature_invalid",
      "descriptor_digest_mismatch",
      "authority_not_recognized",
      "route_unattested",
      "stale_rejected",
    ]);
    if (profile.controls.evidence.require_feed_descriptors) {
      descriptorFailureReasons.add("missing_feed_descriptor");
    }
    for (const [name, reportValue] of Object.entries(this.lastFeedDescriptorEvidence)) {
      const report = reportValue as Record<string, unknown>;
      const reason = report.reason_code as string | undefined;
      const feedPolicy = descriptorPolicy[name] ?? "observe";
      const mustFail = feedPolicy === "fail" || Boolean(profile.controls.evidence.require_feed_descriptors);
      if (reason && descriptorFailureReasons.has(reason) && mustFail) {
        failures.push(`${name} feed descriptor: ${reason}`);
      }
    }
    return [failures.length === 0, failures];
  }

  private transportOrRevocationFailureResult(
    profile: VerificationProfile,
    freshness: string,
    explanation: string,
  ): VerificationResult {
    const failClosed =
      profile.controls.failure.network_failure === "fail_closed" || profile.controls.revocation.enforcement === "fail";
    const trustOutcome = failClosed ? "rejected" : "deferred";
    return createVerificationResult({
      asset_integrity: "verified",
      assertion_binding: "verified",
      issuer_recognition: "unknown",
      actor_authorization: "unknown",
      process_integrity: "unknown",
      policy_freshness: freshness,
      verification_mode: "transport_guardrail",
      trust_outcome: trustOutcome,
      policy_evidence: {
        verification_profile: verificationProfileToDict(profile),
        transport: this.lastTransportMetadata,
        revocation_status: this.lastRevocationStatus,
        feed_descriptors: this.lastFeedDescriptorEvidence,
      },
      explanations: [explanation],
    });
  }

  private serviceUnavailableResult(profile: VerificationProfile): VerificationResult {
    const failClosed = profile.controls.failure.network_failure === "fail_closed";
    const trustOutcome = failClosed ? "rejected" : "deferred";
    const explanation = failClosed
      ? "No service or gateway available for live authorization lookup; profile requires fail-closed handling"
      : "No service or gateway available for live authorization lookup";
    return createVerificationResult({
      asset_integrity: "verified",
      assertion_binding: "verified",
      issuer_recognition: "unknown",
      actor_authorization: "unknown",
      process_integrity: "unknown",
      policy_freshness: "service_unavailable",
      verification_mode: profile.controls.freshness.require_live ? "online_full" : "cached_online",
      trust_outcome: trustOutcome,
      policy_evidence: {
        verification_profile: verificationProfileToDict(profile),
        transport: this.lastTransportMetadata,
        revocation_status: this.lastRevocationStatus,
        feed_descriptors: this.lastFeedDescriptorEvidence,
      },
      explanations: [explanation],
    });
  }

  /**
   * MockTRQPService's in-memory lookups never fail, but a real PolicyService
   * backend (network calls) can reject at any point during the online lookup.
   * Route that the same way an unconfigured service is routed - through the
   * profile's fail_open/fail_closed control - rather than letting the error
   * propagate uncaught out of verify().
   */
  private serviceErrorResult(profile: VerificationProfile, error: unknown): VerificationResult {
    const failClosed = profile.controls.failure.network_failure === "fail_closed";
    const trustOutcome = failClosed ? "rejected" : "deferred";
    const message = error instanceof Error ? error.message : String(error);
    const explanation = failClosed
      ? `Live policy service call failed: ${message}; profile requires fail-closed handling`
      : `Live policy service call failed: ${message}`;
    return createVerificationResult({
      asset_integrity: "verified",
      assertion_binding: "verified",
      issuer_recognition: "unknown",
      actor_authorization: "unknown",
      process_integrity: "unknown",
      policy_freshness: "service_error",
      verification_mode: profile.controls.freshness.require_live ? "online_full" : "cached_online",
      trust_outcome: trustOutcome,
      policy_evidence: {
        verification_profile: verificationProfileToDict(profile),
        transport: this.lastTransportMetadata,
        revocation_status: this.lastRevocationStatus,
        feed_descriptors: this.lastFeedDescriptorEvidence,
      },
      explanations: [explanation],
    });
  }

  private verifyEdge(
    request: VerificationRequest,
    recContext: Record<string, unknown>,
    profile: VerificationProfile,
  ): VerificationResult {
    this.lastTransportMetadata = {
      required: { ...profile.controls.transport },
      actual: feedTransportMetadataToDict(
        createFeedTransportMetadata({
          mode: "local",
          integrity: "signed",
          available: this.snapshot !== null,
          channel: "snapshot",
        }),
      ),
      violations: [],
      satisfied: true,
    };
    this.lastRevocationStatus = {
      source: "snapshot",
      channel: "snapshot",
      freshness_ok: true,
      violations: [],
      max_age_seconds: profile.controls.revocation.max_age_seconds,
    };
    if (this.snapshot === null) {
      return createVerificationResult({
        asset_integrity: "verified",
        assertion_binding: "verified",
        issuer_recognition: "unknown",
        actor_authorization: "unknown",
        process_integrity: "unknown",
        policy_freshness: "missing_snapshot",
        verification_mode: "offline_snapshot",
        trust_outcome: profile.controls.authority.trust_anchors_required ? "rejected" : "deferred",
        policy_evidence: {
          verification_profile: verificationProfileToDict(profile),
          transport: this.lastTransportMetadata,
          revocation_status: this.lastRevocationStatus,
          feed_descriptors: this.lastFeedDescriptorEvidence,
        },
        explanations: ["No snapshot available for edge verification"],
      });
    }

    if (!this.snapshot.isUsable()) {
      return createVerificationResult({
        asset_integrity: "verified",
        assertion_binding: "verified",
        issuer_recognition: "unknown",
        actor_authorization: "unknown",
        process_integrity: "unknown",
        policy_freshness: this.snapshot.status(),
        verification_mode: "offline_snapshot",
        trust_outcome: "rejected",
        policy_evidence: {
          verification_profile: verificationProfileToDict(profile),
          transport: this.lastTransportMetadata,
          revocation_status: this.lastRevocationStatus,
          feed_descriptors: this.lastFeedDescriptorEvidence,
        },
        explanations: this.snapshot.validationErrors.map((err) => `Snapshot validation failed: ${err}`),
      });
    }

    const auth = this.snapshot.findAuthorization(
      request.entity_id,
      request.authority_id,
      request.action,
      request.resource,
      request.context,
    );
    let rec: Record<string, unknown> | null = null;
    if (request.issuer_id) {
      rec = this.snapshot.findRecognition(request.authority_id, request.issuer_id, recContext);
    }
    return this.synthesizeResult({
      auth,
      rec,
      freshness: this.snapshot.status(),
      mode: "offline_snapshot",
      request,
      profile,
    });
  }

  private async verifyOnline(
    request: VerificationRequest,
    authKey: string,
    recKey: string,
    recContext: Record<string, unknown>,
    forceLive: boolean,
    profile: VerificationProfile,
  ): Promise<VerificationResult> {
    if (this.service === null && this.gateway === null) {
      this.lastTransportMetadata = {
        required: { ...profile.controls.transport },
        actual: feedTransportMetadataToDict(
          createFeedTransportMetadata({ mode: "local", integrity: "none", available: false, channel: "none" }),
        ),
        violations: [],
        satisfied: false,
      };
      this.lastRevocationStatus = { source: "none", freshness_ok: false, violations: ["no revocation source available"] };
      return this.serviceUnavailableResult(profile);
    }

    try {
      return await this.verifyOnlineUnsafe(request, authKey, recKey, recContext, forceLive, profile);
    } catch (error) {
      return this.serviceErrorResult(profile, error);
    }
  }

  /**
   * The part of verifyOnline that actually calls out to the configured
   * service/gateway. Split out so verifyOnline can wrap it in a single
   * try/catch - a real PolicyService backend can reject at any of several
   * points below (transport/revocation checks, authorization, recognition).
   */
  private async verifyOnlineUnsafe(
    request: VerificationRequest,
    authKey: string,
    recKey: string,
    recContext: Record<string, unknown>,
    forceLive: boolean,
    profile: VerificationProfile,
  ): Promise<VerificationResult> {
    const [transportOk, transportFailures] = this.evaluateTransport(profile);
    const [revocationOk, revocationFailures] = await this.evaluateRevocationFreshness(profile);
    if (!transportOk) {
      return this.transportOrRevocationFailureResult(profile, "transport_violation", transportFailures.join("; "));
    }
    if (!revocationOk && profile.controls.revocation.enforcement === "fail") {
      return this.transportOrRevocationFailureResult(profile, "revocation_stale", revocationFailures.join("; "));
    }

    let auth = forceLive ? null : ((await this.cache.get(authKey)) ?? null);
    let rec = forceLive ? null : ((await this.cache.get(recKey)) ?? null);
    const explanations = [`Verification profile: ${profile.id}`];
    let gatewayMediation: Record<string, unknown> = {};
    if (revocationFailures.length) {
      explanations.push(revocationFailures.join("; "));
    }

    if (auth === null) {
      if (this.service === null && this.gateway === null) {
        return this.serviceUnavailableResult(profile);
      }
      if (this.gateway !== null) {
        const [authResult, mediation] = await this.gateway.authorization(
          request.entity_id,
          request.authority_id,
          request.action,
          request.resource,
          request.context,
        );
        auth = authResult;
        gatewayMediation = mediation;
        explanations.push("Trust gateway mediated authorization lookup");
      } else {
        auth = (await this.service!.authorization(
          request.entity_id,
          request.authority_id,
          request.action,
          request.resource,
          request.context,
        )) as unknown as Record<string, unknown>;
        explanations.push("Live authorization lookup executed");
      }
      await this.cache.set(authKey, auth, "medium");
    } else {
      explanations.push("Authorization cache hit");
    }

    if (request.issuer_id) {
      if (rec === null) {
        if (this.gateway !== null) {
          const [recResult, recMediation] = await this.gateway.recognition(request.authority_id, request.issuer_id, recContext);
          rec = recResult;
          gatewayMediation = { ...gatewayMediation, recognition: recMediation };
          await this.cache.set(recKey, rec, "medium");
          explanations.push("Trust gateway mediated recognition lookup");
        } else if (this.service !== null) {
          rec = (await this.service.recognition(request.authority_id, request.issuer_id, recContext)) as unknown as Record<
            string,
            unknown
          >;
          await this.cache.set(recKey, rec, "medium");
          explanations.push("Live recognition lookup executed");
        }
      } else {
        explanations.push("Recognition cache hit");
      }
    }

    const result = this.synthesizeResult({
      auth,
      rec,
      freshness: revocationOk ? "fresh" : "stale_but_warned",
      mode: this.gateway !== null ? "gateway_mediated" : forceLive ? "online_full" : "cached_online",
      request,
      profile,
      gatewayMediation,
    });
    result.explanations.push(...explanations);
    return result;
  }

  private appraiseProcess(
    request: VerificationRequest,
    policyRequirements: Record<string, unknown>,
  ): [string, Record<string, unknown>, string[], boolean] {
    const evidence = request.process_evidence ?? {};
    const summary: Record<string, unknown> = {
      status: "not_evaluated",
      process_type: evidence.process_type ?? null,
      confidence: evidence.confidence ?? null,
      minimum_confidence: policyRequirements.min_process_integrity ?? null,
      evidence_ref: evidence.evidence_ref ?? null,
      evidence_format: evidence.evidence_format ?? null,
      appraisal: evidence.appraisal ?? null,
      reference: evidence.reference ?? null,
    };
    const explanations: string[] = [];
    const requiresProcess = Boolean(policyRequirements.requires_process_proof);
    if (!requiresProcess) {
      summary.status = "not_required";
      return ["not_required", summary, explanations, true];
    }

    if (!Object.keys(evidence).length) {
      summary.status = "missing_required_proof";
      return [
        "missing_required_proof",
        summary,
        ["Policy requires process proof but request did not include process evidence"],
        false,
      ];
    }

    const verified = Boolean(evidence.verified);
    const processType = evidence.process_type as string | undefined;
    const confidence = Number(evidence.confidence ?? 0) || 0;
    const minConfidence = Number(policyRequirements.min_process_integrity ?? 0) || 0;
    const allowedTypes = (policyRequirements.allowed_process_types as string[] | undefined) ?? [];

    summary.status = verified ? "verified" : "failed";
    let passes = verified;

    if (allowedTypes.length && !allowedTypes.includes(processType as string)) {
      passes = false;
      explanations.push(`Process type ${processType} is not allowed by policy`);
    }

    if (confidence < minConfidence) {
      passes = false;
      explanations.push(`Process confidence ${confidence.toFixed(2)} is below policy minimum ${minConfidence.toFixed(2)}`);
    }

    if (!passes) {
      if (!verified) {
        return ["failed", summary, explanations, false];
      }
      return ["insufficient", summary, explanations, false];
    }

    if (confidence >= 0.85) {
      return ["verified_high", summary, explanations, true];
    }
    return ["verified", summary, explanations, true];
  }

  private synthesizeResult({
    auth,
    rec,
    freshness,
    mode,
    request,
    profile,
    gatewayMediation,
  }: {
    auth: Record<string, unknown> | null;
    rec: Record<string, unknown> | null;
    freshness: string;
    mode: string;
    request: VerificationRequest;
    profile: VerificationProfile;
    gatewayMediation?: Record<string, unknown>;
  }): VerificationResult {
    let actorAuthorization = auth && auth.authorized ? "authorized" : "not_authorized";
    const issuerRecognition = rec && rec.recognized ? "recognized" : "unknown";
    const policyRequirements = (auth?.policy_requirements as Record<string, unknown> | undefined) ?? {};
    const [processIntegrity, processAppraisal, processExplanationsInit, processOkInit] = this.appraiseProcess(
      request,
      policyRequirements,
    );
    let processOk = processOkInit;
    let processExplanations = processExplanationsInit;
    const policyEvidence: Record<string, unknown> = {
      authorization_evidence: auth?.evidence ?? [],
      recognition_evidence: rec?.evidence ?? [],
      policy_epoch: auth?.policy_epoch ?? null,
      policy_requirements: policyRequirements,
      verification_profile: verificationProfileToDict(profile),
      transport: this.lastTransportMetadata,
      revocation_status: this.lastRevocationStatus,
      feed_descriptors: this.lastFeedDescriptorEvidence,
    };

    if (auth === null) {
      const trustOutcome = profile.controls.failure.policy_unavailable === "fail_closed" ? "rejected" : "deferred";
      return createVerificationResult({
        asset_integrity: "verified",
        assertion_binding: "verified",
        issuer_recognition: issuerRecognition,
        actor_authorization: "unknown",
        process_integrity: processIntegrity,
        policy_freshness: freshness,
        verification_mode: mode,
        trust_outcome: trustOutcome,
        process_appraisal: processAppraisal,
        policy_evidence: policyEvidence,
        gateway_mediation: gatewayMediation ?? {},
        explanations: processExplanations,
      });
    }

    if (actorAuthorization === "authorized" && issuerRecognition === "unknown" && !profile.controls.authority.allow_untrusted) {
      actorAuthorization = "not_authorized";
      processOk = false;
      processExplanations = [
        "Authorization matched but issuer recognition is required by profile authority controls",
        ...processExplanations,
      ];
    }

    let trustOutcome = actorAuthorization === "authorized" ? "trusted" : "rejected";
    const explanations = [...processExplanations];
    if (actorAuthorization === "authorized" && !processOk) {
      trustOutcome = "rejected";
      explanations.unshift("Authorization passed but process policy requirements were not met");
    }
    if (mode === "offline_snapshot" && actorAuthorization === "authorized" && processOk) {
      trustOutcome = "trusted_cached";
    }

    return createVerificationResult({
      asset_integrity: "verified",
      assertion_binding: "verified",
      issuer_recognition: issuerRecognition,
      actor_authorization: actorAuthorization,
      process_integrity: processIntegrity,
      policy_freshness: freshness,
      verification_mode: mode,
      trust_outcome: trustOutcome,
      process_appraisal: processAppraisal,
      policy_evidence: policyEvidence,
      gateway_mediation: gatewayMediation ?? {},
      explanations,
    });
  }
}
