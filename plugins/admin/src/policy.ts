import type {
  AuthorizationResponse,
  FeedTransportMetadata,
  PolicyService,
  RecognitionResponse,
} from "@cognitiveproof/cawg-trqp-plugin-types";
import { createAuthorizationResponse, createFeedTransportMetadata, createRecognitionResponse } from "@cognitiveproof/cawg-trqp-plugin-types";
import type { AdminStore } from "./store.js";
import type { Grant } from "./types.js";

export interface AdminPolicyServiceOptions {
  store: AdminStore;
  /** Answers recognition queries, which grants don't model. Default: never recognized. */
  recognition?: PolicyService;
  now?: () => Date;
}

/** Every key in the grant's stored context must match the request (TRQP's `time` excepted). */
function contextMatches(request: Record<string, unknown>, stored: Record<string, unknown>): boolean {
  return Object.entries(stored).every(([key, value]) => key === "time" || request[key] === value);
}

function at(value: string | null): number | null {
  if (value === null) return null;
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : t;
}

type GrantState = "active" | "not_yet_granted" | "revoked" | "expired";

function stateAt(grant: Grant, time: number): GrantState {
  const granted = at(grant.granted_at) ?? Number.POSITIVE_INFINITY;
  const revoked = at(grant.revoked_at);
  const expires = at(grant.expires);
  if (time < granted) return "not_yet_granted";
  if (revoked !== null && time >= revoked) return "revoked";
  if (expires !== null && time >= expires) return "expired";
  return "active";
}

/**
 * A PolicyService answering TRQP authorization queries from the grants
 * RegistryAdmin manages. It is time-aware: a query whose context carries
 * `time` (TRQP's point-in-time query) is answered as of that moment, so a
 * revocation stops authorization from then on without changing the answer
 * for earlier times. Without `time`, the query is answered for now.
 */
export class AdminPolicyService implements PolicyService {
  readonly transportMetadata: FeedTransportMetadata;
  private readonly store: AdminStore;
  private readonly fallback: PolicyService | undefined;
  private readonly now: () => Date;

  constructor(options: AdminPolicyServiceOptions) {
    this.store = options.store;
    this.fallback = options.recognition;
    this.now = options.now ?? (() => new Date());
    this.transportMetadata = createFeedTransportMetadata({ mode: "http", integrity: "tls", available: true, channel: "live" });
  }

  async authorization(
    entityId: string,
    authorityId: string,
    action: string,
    resource: string,
    context: Record<string, unknown>,
  ): Promise<AuthorizationResponse> {
    let time = this.now().getTime();
    if (typeof context.time === "string" && context.time !== "") {
      const requested = at(context.time);
      if (requested === null) return createAuthorizationResponse({ authorized: false, reason: "invalid_context_time" });
      time = requested;
    }

    const grants = (await this.store.listGrants({ entity_id: entityId, authority_id: authorityId, action, resource })).filter((g) =>
      contextMatches(context, g.context),
    );
    if (grants.length === 0) return createAuthorizationResponse({ authorized: false, reason: "no_matching_policy" });

    const states = grants.map((g) => ({ grant: g, state: stateAt(g, time) }));
    const active = states.find((s) => s.state === "active");
    if (active) {
      return createAuthorizationResponse({
        authorized: true,
        expires: active.grant.expires,
        policy_epoch: active.grant.policy_epoch,
        evidence: [`grant:${active.grant.id}`, ...active.grant.evidence],
      });
    }
    // Report the most relevant reason: a revocation or expiry outranks "not yet granted".
    const reason = (["revoked", "expired", "not_yet_granted"] as const).find((r) => states.some((s) => s.state === r))!;
    const relevant = states.find((s) => s.state === reason)!.grant;
    return createAuthorizationResponse({
      authorized: false,
      reason,
      policy_epoch: relevant.policy_epoch,
      evidence: [`grant:${relevant.id}`, ...relevant.evidence],
    });
  }

  async recognition(
    entityId: string,
    authorityId: string,
    action: string,
    resource: string,
    context: Record<string, unknown>,
  ): Promise<RecognitionResponse> {
    if (this.fallback) return this.fallback.recognition(entityId, authorityId, action, resource, context);
    return createRecognitionResponse({ recognized: false, reason: "not_recognized" });
  }

  /**
   * Grants are read live from the store on every query, so revocation state
   * is always current. Revocation is per grant and time-bounded rather than a
   * global entity denylist, so no globally revoked entities are reported.
   */
  async revocationStatus(): Promise<Record<string, unknown>> {
    return {
      issued_at: this.now().toISOString(),
      policy_epoch: null,
      channel: "live",
      age_seconds: 0,
      revoked_entities: [],
      feed_descriptor: {},
    };
  }

  async feedDescriptorEvidence(): Promise<Record<string, unknown>> {
    return {};
  }
}
