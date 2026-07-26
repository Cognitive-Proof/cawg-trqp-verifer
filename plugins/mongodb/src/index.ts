import type {
  AuthorizationResponse,
  FeedTransportMetadata,
  PolicyService,
  RecognitionResponse,
} from "@cognitiveproof/cawg-trqp-plugin-types";
import { createAuthorizationResponse, createFeedTransportMetadata, createRecognitionResponse } from "@cognitiveproof/cawg-trqp-plugin-types";
import { getCollection, type MongoConnectionOptions } from "./client.js";

// Reference collection shapes. A production deployment is free to use a
// richer schema; this scaffold mirrors the JSON shape the core package's
// MockTRQPService reads from data/policies.json and data/revocations.json so
// migrating from the mock is a straightforward document copy.
interface AuthorizationDoc {
  entity_id: string;
  authority_id: string;
  action: string;
  resource: string;
  context?: Record<string, unknown>;
  authorized: boolean;
  expires?: string | null;
  policy_epoch?: string | null;
  evidence?: string[];
  reason?: string | null;
  policy_requirements?: Record<string, unknown>;
}

interface RecognitionDoc {
  authority_id: string;
  recognized_authority_id: string;
  context?: Record<string, unknown>;
  recognized: boolean;
  expires?: string | null;
  policy_epoch?: string | null;
  evidence?: string[];
  reason?: string | null;
}

interface RevocationDoc {
  revoked_entities?: string[];
  policy_epoch?: string | null;
  issued_at?: string | null;
  channel?: string;
}

function contextMatches(requestContext: Record<string, unknown>, storedContext: Record<string, unknown>): boolean {
  return Object.entries(storedContext).every(([key, value]) => requestContext[key] === value);
}

function ageSeconds(issuedAt: string | null | undefined): number | null {
  if (!issuedAt) return null;
  const issued = new Date(issuedAt);
  if (Number.isNaN(issued.getTime())) return null;
  return Math.max(Math.trunc((Date.now() - issued.getTime()) / 1000), 0);
}

export interface MongoPolicyServiceOptions extends MongoConnectionOptions {
  authorizationsCollection?: string;
  recognitionsCollection?: string;
  revocationsCollection?: string;
}

/**
 * MongoDB-backed PolicyService. Authorization/recognition documents are
 * matched by entity/authority/action/resource (or authority/recognized
 * authority) via a MongoDB query, then filtered by context in application
 * code - this deliberately mirrors MockTRQPService's subset-match semantics
 * (every key present in the stored context must match the request's
 * context; the request may carry additional keys) rather than relying on
 * MongoDB's exact-subdocument-equality query semantics, which would reject
 * a match whenever key order differs or extra request context keys exist.
 */
export class MongoPolicyService implements PolicyService {
  readonly transportMetadata: FeedTransportMetadata;
  private readonly options: MongoConnectionOptions;
  private readonly collections: Required<Pick<MongoPolicyServiceOptions, "authorizationsCollection" | "recognitionsCollection" | "revocationsCollection">>;

  constructor(options: MongoPolicyServiceOptions = {}) {
    this.options = { uri: options.uri, dbName: options.dbName };
    this.collections = {
      authorizationsCollection: options.authorizationsCollection ?? "authorizations",
      recognitionsCollection: options.recognitionsCollection ?? "recognitions",
      revocationsCollection: options.revocationsCollection ?? "revocations",
    };
    this.transportMetadata = createFeedTransportMetadata({
      mode: "http",
      integrity: "tls",
      available: true,
      channel: "live",
    });
  }

  private async revocationDoc(): Promise<RevocationDoc | null> {
    const col = await getCollection<RevocationDoc>(this.collections.revocationsCollection, this.options);
    return col.findOne({});
  }

  async authorization(
    entityId: string,
    authorityId: string,
    action: string,
    resource: string,
    context: Record<string, unknown>,
  ): Promise<AuthorizationResponse> {
    const revocation = await this.revocationDoc();
    if (revocation?.revoked_entities?.includes(entityId)) {
      return createAuthorizationResponse({
        authorized: false,
        reason: "entity_revoked",
        policy_epoch: revocation.policy_epoch ?? null,
      });
    }

    const col = await getCollection<AuthorizationDoc>(this.collections.authorizationsCollection, this.options);
    const candidates = await col
      .find({ entity_id: entityId, authority_id: authorityId, action, resource })
      .toArray();
    const match = candidates.find((doc) => contextMatches(context, doc.context ?? {}));
    if (!match) {
      return createAuthorizationResponse({ authorized: false, reason: "no_matching_policy" });
    }
    return createAuthorizationResponse({
      authorized: Boolean(match.authorized),
      expires: match.expires ?? null,
      policy_epoch: match.policy_epoch ?? null,
      evidence: match.evidence ?? [],
      reason: match.reason ?? null,
      policy_requirements: match.policy_requirements ?? {},
    });
  }

  async recognition(
    authorityId: string,
    recognizedAuthorityId: string,
    context: Record<string, unknown>,
  ): Promise<RecognitionResponse> {
    const col = await getCollection<RecognitionDoc>(this.collections.recognitionsCollection, this.options);
    const candidates = await col
      .find({ authority_id: authorityId, recognized_authority_id: recognizedAuthorityId })
      .toArray();
    const match = candidates.find((doc) => contextMatches(context, doc.context ?? {}));
    if (!match) {
      return createRecognitionResponse({ recognized: false, reason: "not_recognized" });
    }
    return createRecognitionResponse({
      recognized: Boolean(match.recognized),
      expires: match.expires ?? null,
      policy_epoch: match.policy_epoch ?? null,
      evidence: match.evidence ?? [],
      reason: match.reason ?? null,
    });
  }

  async revocationStatus(): Promise<Record<string, unknown>> {
    const revocation = await this.revocationDoc();
    return {
      issued_at: revocation?.issued_at ?? null,
      policy_epoch: revocation?.policy_epoch ?? null,
      channel: revocation?.channel ?? "snapshot",
      age_seconds: ageSeconds(revocation?.issued_at),
      // This reference scaffold doesn't track signed feed-descriptor evidence
      // for the revocation feed; extend this if your deployment needs it.
      feed_descriptor: {},
    };
  }

  async feedDescriptorEvidence(): Promise<Record<string, unknown>> {
    // No signed feed descriptors tracked at the database layer in this
    // reference scaffold - see revocationStatus() above.
    return {};
  }
}

export default MongoPolicyService;
