// Shared contract for cawg-trqp-refimpl storage/cache plugins. A plugin
// (Redis, MongoDB, MySQL, Postgres, or anything else) implements one or more
// of the interfaces below and is passed directly into `Verifier` /
// `HTTPTRQPService` / `TRQPService` from the core package - no registration
// step, just constructor injection. This package has no dependency on the
// core package (or vice versa isn't required either): it's the neutral
// contract both sides depend on.

export interface FeedTransportMetadata {
  mode: string;
  integrity: string;
  available: boolean;
  channel: string;
}

export function createFeedTransportMetadata(
  fields: Partial<FeedTransportMetadata> & Pick<FeedTransportMetadata, "mode" | "integrity">,
): FeedTransportMetadata {
  return {
    available: true,
    channel: "full",
    ...fields,
  };
}

export function feedTransportMetadataToDict(metadata: FeedTransportMetadata): Record<string, unknown> {
  return {
    mode: metadata.mode,
    integrity: metadata.integrity,
    available: metadata.available,
    channel: metadata.channel,
  };
}

export interface AuthorizationResponse {
  authorized: boolean;
  expires: string | null;
  policy_epoch: string | null;
  evidence: string[];
  reason: string | null;
  policy_requirements: Record<string, unknown>;
}

export function createAuthorizationResponse(
  fields: Partial<AuthorizationResponse> & Pick<AuthorizationResponse, "authorized">,
): AuthorizationResponse {
  return {
    expires: null,
    policy_epoch: null,
    evidence: [],
    reason: null,
    policy_requirements: {},
    ...fields,
  };
}

export interface RecognitionResponse {
  recognized: boolean;
  expires: string | null;
  policy_epoch: string | null;
  evidence: string[];
  reason: string | null;
}

export function createRecognitionResponse(
  fields: Partial<RecognitionResponse> & Pick<RecognitionResponse, "recognized">,
): RecognitionResponse {
  return {
    expires: null,
    policy_epoch: null,
    evidence: [],
    reason: null,
    ...fields,
  };
}

/**
 * A PolicyService answers TRQP policy questions - whether that's an
 * in-memory mock reading local JSON (the core package's MockTRQPService) or a
 * real network/database-backed client (a plugin). transportMetadata is a
 * plain synchronous property (not a lookup) because it describes how this
 * service is configured to be reached, not a live result; everything else
 * does real work and is async even where an implementation resolves
 * instantly.
 */
export interface PolicyService {
  transportMetadata: FeedTransportMetadata;

  authorization(
    entityId: string,
    authorityId: string,
    action: string,
    resource: string,
    context: Record<string, unknown>,
  ): Promise<AuthorizationResponse>;

  recognition(
    authorityId: string,
    recognizedAuthorityId: string,
    context: Record<string, unknown>,
  ): Promise<RecognitionResponse>;

  revocationStatus(): Promise<Record<string, unknown>>;

  feedDescriptorEvidence(): Promise<Record<string, unknown>>;
}

/**
 * Contract for anything that can cache verifier decisions. Async because a
 * real implementation (Redis, Memcached, some other shared store) has to do
 * network I/O; callers must always await these so a distributed
 * implementation is a true drop-in replacement for an in-memory one.
 */
export interface DecisionCache<T = unknown> {
  set(key: string, value: T, ttlClass?: string): Promise<void>;
  get(key: string): Promise<T | undefined>;
  invalidate(key: string): Promise<void>;
}

export interface RevocationCheckResult {
  revoked: boolean;
  reason: string | null;
  policyEpoch: string | null;
}

/**
 * Contract for tracking an urgent, out-of-band revocation delta pushed into a
 * running verifier between normal policy refresh cycles. Async so a shared
 * backend (Redis, a pub/sub-fed store, etc.) is a real drop-in: an in-memory
 * implementation only affects the single process it's constructed in, which
 * is fine for one instance but silently has no effect on any other instance
 * in a horizontally-scaled deployment.
 */
export interface RevocationDeltaStore {
  set(revokedEntities: string[], policyEpoch?: string | null): Promise<void>;
  check(entityId: string): Promise<RevocationCheckResult>;
}
