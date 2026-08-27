import type {
  AuthorizationResponse,
  FeedTransportMetadata,
  PolicyService,
  RecognitionResponse,
} from "@cognitiveproof/cawg-trqp-plugin-types";
import { createAuthorizationResponse, createFeedTransportMetadata, createRecognitionResponse } from "@cognitiveproof/cawg-trqp-plugin-types";
import { getPostgresPool, type PostgresConnectionOptions } from "./client.js";

// Reference table shapes - see README.md for CREATE TABLE statements. This
// scaffold mirrors the JSON shape the core package's MockTRQPService reads
// from data/policies.json and data/revocations.json.
interface AuthorizationRow {
  entity_id: string;
  authority_id: string;
  action: string;
  resource: string;
  context: unknown;
  authorized: boolean;
  expires: string | null;
  policy_epoch: string | null;
  evidence: unknown;
  reason: string | null;
  policy_requirements: unknown;
}

interface RecognitionRow {
  entity_id: string;
  authority_id: string;
  action: string;
  resource: string;
  context: unknown;
  recognized: boolean;
  expires: string | null;
  policy_epoch: string | null;
  evidence: unknown;
  reason: string | null;
}

interface RevocationRow {
  revoked_entities: unknown;
  policy_epoch: string | null;
  issued_at: string | null;
  channel: string | null;
}

// node-postgres parses jsonb/json columns into JS values automatically, but
// parse defensively in case a deployment stores these as plain text columns.
function parseJsonColumn<T>(value: unknown, fallback: T): T {
  if (value === null || value === undefined) return fallback;
  if (typeof value === "string") {
    try {
      return JSON.parse(value) as T;
    } catch {
      return fallback;
    }
  }
  return value as T;
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

export interface PostgresPolicyServiceOptions extends PostgresConnectionOptions {
  authorizationsTable?: string;
  recognitionsTable?: string;
  revocationsTable?: string;
}

/**
 * Postgres-backed PolicyService. Authorization/recognition rows are matched
 * by entity/authority/action/resource (or authority/recognized authority)
 * via a SQL WHERE clause, then filtered by context in application code -
 * this deliberately mirrors MockTRQPService's subset-match semantics (every
 * key present in the stored context must match the request's context; the
 * request may carry additional keys) rather than a jsonb containment (`@>`)
 * predicate, which would reject a match whenever the request supplies extra
 * context keys the stored row doesn't have an opinion on.
 */
export class PostgresPolicyService implements PolicyService {
  readonly transportMetadata: FeedTransportMetadata;
  private readonly uri?: string;
  private readonly tables: Required<Pick<PostgresPolicyServiceOptions, "authorizationsTable" | "recognitionsTable" | "revocationsTable">>;

  constructor(options: PostgresPolicyServiceOptions = {}) {
    this.uri = options.uri;
    this.tables = {
      authorizationsTable: options.authorizationsTable ?? "authorizations",
      recognitionsTable: options.recognitionsTable ?? "recognitions",
      revocationsTable: options.revocationsTable ?? "revocations",
    };
    this.transportMetadata = createFeedTransportMetadata({
      mode: "http",
      integrity: "tls",
      available: true,
      channel: "live",
    });
  }

  private async revocationRow(): Promise<RevocationRow | undefined> {
    const pool = getPostgresPool(this.uri);
    const result = await pool.query<RevocationRow>(`SELECT * FROM ${this.tables.revocationsTable} LIMIT 1`);
    return result.rows[0];
  }

  async authorization(
    entityId: string,
    authorityId: string,
    action: string,
    resource: string,
    context: Record<string, unknown>,
  ): Promise<AuthorizationResponse> {
    const revocation = await this.revocationRow();
    const revokedEntities = parseJsonColumn<string[]>(revocation?.revoked_entities, []);
    if (revokedEntities.includes(entityId)) {
      return createAuthorizationResponse({
        authorized: false,
        reason: "entity_revoked",
        policy_epoch: revocation?.policy_epoch ?? null,
      });
    }

    const pool = getPostgresPool(this.uri);
    const result = await pool.query<AuthorizationRow>(
      `SELECT * FROM ${this.tables.authorizationsTable} WHERE entity_id = $1 AND authority_id = $2 AND action = $3 AND resource = $4`,
      [entityId, authorityId, action, resource],
    );
    const match = result.rows.find((row) => contextMatches(context, parseJsonColumn(row.context, {})));
    if (!match) {
      return createAuthorizationResponse({ authorized: false, reason: "no_matching_policy" });
    }
    return createAuthorizationResponse({
      authorized: Boolean(match.authorized),
      expires: match.expires ?? null,
      policy_epoch: match.policy_epoch ?? null,
      evidence: parseJsonColumn(match.evidence, []),
      reason: match.reason ?? null,
      policy_requirements: parseJsonColumn(match.policy_requirements, {}),
    });
  }

  async recognition(
    entityId: string,
    authorityId: string,
    action: string,
    resource: string,
    context: Record<string, unknown>,
  ): Promise<RecognitionResponse> {
    const pool = getPostgresPool(this.uri);
    const result = await pool.query<RecognitionRow>(
      `SELECT * FROM ${this.tables.recognitionsTable} WHERE entity_id = $1 AND authority_id = $2 AND action = $3 AND resource = $4`,
      [entityId, authorityId, action, resource],
    );
    const match = result.rows.find((row) => contextMatches(context, parseJsonColumn(row.context, {})));
    if (!match) {
      return createRecognitionResponse({ recognized: false, reason: "not_recognized" });
    }
    return createRecognitionResponse({
      recognized: Boolean(match.recognized),
      expires: match.expires ?? null,
      policy_epoch: match.policy_epoch ?? null,
      evidence: parseJsonColumn(match.evidence, []),
      reason: match.reason ?? null,
    });
  }

  async revocationStatus(): Promise<Record<string, unknown>> {
    const revocation = await this.revocationRow();
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

export default PostgresPolicyService;
