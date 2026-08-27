import { readFileSync } from "node:fs";
import { canonicalJsonAsciiText } from "./jsoncanon.js";
import { createFeedTransportMetadata, type FeedTransportMetadata } from "./transport.js";
import { loadFeedDescriptor, validateFeedDescriptor, type FeedValidationReport } from "./feed_descriptor.js";
import {
  createAuthorizationResponse,
  createRecognitionResponse,
  type AuthorizationResponse,
  type RecognitionResponse,
} from "./models.js";
import type { PolicyService } from "./policy_service.js";

function parseUtc(ts: string | null | undefined): Date | null {
  if (!ts) return null;
  const date = new Date(ts);
  return Number.isNaN(date.getTime()) ? null : date;
}

function contextMatches(requestContext: Record<string, unknown>, itemContext: Record<string, unknown>): boolean {
  return Object.entries(itemContext).every(([key, value]) => requestContext[key] === value);
}

export interface MockTRQPServiceOptions {
  transportMode?: string;
  transportIntegrity?: string;
  transportAvailable?: boolean;
  policyDescriptorPath?: string | null;
  revocationDescriptorPath?: string | null;
  trustAnchorsPath?: string | null;
}

const EXPECTED_AUTHORITIES = new Set(["did:web:media-registry.example"]);

export class MockTRQPService implements PolicyService {
  readonly policyPath: string;
  readonly policyBodyText: string;
  readonly data: Record<string, unknown>;
  revocations: Record<string, unknown>;
  revocationBodyText: string;
  readonly transportMetadata: FeedTransportMetadata;
  readonly policyDescriptor: Record<string, unknown> | null;
  readonly revocationDescriptor: Record<string, unknown> | null;
  readonly trustAnchors: Record<string, unknown> | null;
  readonly feedValidation: { policy: FeedValidationReport; revocation: FeedValidationReport };

  constructor(policyPath: string, revocationPath: string | null = null, options: MockTRQPServiceOptions = {}) {
    this.policyPath = policyPath;
    this.policyBodyText = readFileSync(policyPath, "utf-8");
    this.data = JSON.parse(this.policyBodyText);

    this.revocations = { revoked_entities: [], channel: "delta", issued_at: "2026-12-31T00:00:00Z" };
    this.revocationBodyText = canonicalJsonAsciiText(this.revocations);
    if (revocationPath !== null) {
      this.revocationBodyText = readFileSync(revocationPath, "utf-8");
      this.revocations = JSON.parse(this.revocationBodyText);
    }

    this.transportMetadata = createFeedTransportMetadata({
      mode: options.transportMode ?? "http",
      integrity: options.transportIntegrity ?? "tls",
      available: options.transportAvailable ?? true,
      channel: (this.revocations.channel as string | undefined) ?? "full",
    });

    this.policyDescriptor = loadFeedDescriptor(options.policyDescriptorPath ?? null);
    this.revocationDescriptor = loadFeedDescriptor(options.revocationDescriptorPath ?? null);
    const trustAnchorsPath =
      options.trustAnchorsPath === undefined ? "data/trust_anchors.json" : options.trustAnchorsPath;
    this.trustAnchors = trustAnchorsPath ? JSON.parse(readFileSync(trustAnchorsPath, "utf-8")) : null;

    this.feedValidation = {
      policy: validateFeedDescriptor(this.policyDescriptor, this.policyBodyText, {
        trustAnchors: this.trustAnchors,
        expectedAuthorities: EXPECTED_AUTHORITIES,
      }),
      revocation: validateFeedDescriptor(this.revocationDescriptor, this.revocationBodyText, {
        trustAnchors: this.trustAnchors,
        expectedAuthorities: EXPECTED_AUTHORITIES,
      }),
    };
  }

  async feedDescriptorEvidence(): Promise<Record<string, unknown>> {
    return this.feedValidation as unknown as Record<string, unknown>;
  }

  async authorization(
    entityId: string,
    authorityId: string,
    action: string,
    resource: string,
    context: Record<string, unknown>,
  ): Promise<AuthorizationResponse> {
    const revokedEntities = (this.revocations.revoked_entities as string[] | undefined) ?? [];
    if (revokedEntities.includes(entityId)) {
      return createAuthorizationResponse({
        authorized: false,
        reason: "entity_revoked",
        policy_epoch: (this.revocations.policy_epoch as string | undefined) ?? null,
      });
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
        return createAuthorizationResponse({
          authorized: Boolean(item.authorized ?? false),
          expires: (item.expires as string | undefined) ?? null,
          policy_epoch: (item.policy_epoch as string | undefined) ?? null,
          evidence: (item.evidence as string[] | undefined) ?? [],
          reason: (item.reason as string | undefined) ?? null,
          policy_requirements: (item.policy_requirements as Record<string, unknown> | undefined) ?? {},
        });
      }
    }
    return createAuthorizationResponse({ authorized: false, reason: "no_matching_policy" });
  }

  async recognition(
    entityId: string,
    authorityId: string,
    action: string,
    resource: string,
    context: Record<string, unknown>,
  ): Promise<RecognitionResponse> {
    const items = (this.data.recognition as Record<string, unknown>[] | undefined) ?? [];
    for (const item of items) {
      if (
        item.entity_id === entityId &&
        item.authority_id === authorityId &&
        item.action === action &&
        item.resource === resource &&
        contextMatches(context, (item.context as Record<string, unknown> | undefined) ?? {})
      ) {
        return createRecognitionResponse({
          recognized: Boolean(item.recognized ?? false),
          expires: (item.expires as string | undefined) ?? null,
          policy_epoch: (item.policy_epoch as string | undefined) ?? null,
          evidence: (item.evidence as string[] | undefined) ?? [],
          reason: (item.reason as string | undefined) ?? null,
        });
      }
    }
    return createRecognitionResponse({ recognized: false, reason: "not_recognized" });
  }

  async revocationStatus(): Promise<Record<string, unknown>> {
    const issuedAt = this.revocations.issued_at as string | undefined;
    return {
      issued_at: issuedAt ?? null,
      policy_epoch: (this.revocations.policy_epoch as string | undefined) ?? null,
      channel: (this.revocations.channel as string | undefined) ?? "snapshot",
      age_seconds: this.revocationAgeSeconds(),
      feed_descriptor: this.feedValidation.revocation ?? {},
    };
  }

  revocationAgeSeconds(): number | null {
    const issued = parseUtc(this.revocations.issued_at as string | undefined);
    if (issued === null) return null;
    const deltaSeconds = (Date.now() - issued.getTime()) / 1000;
    return Math.max(Math.trunc(deltaSeconds), 0);
  }
}
