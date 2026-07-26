import type { RowDataPacket } from "mysql2/promise";
import type {
  AuthorizationResponse,
  FeedTransportMetadata,
  PolicyService,
  RecognitionResponse,
} from "@cognitiveproof/cawg-trqp-plugin-types";
import { createAuthorizationResponse, createFeedTransportMetadata, createRecognitionResponse } from "@cognitiveproof/cawg-trqp-plugin-types";
import { getMySQLPool, type MySQLConnectionOptions } from "./client.js";

// Reference table shapes - see README.md for CREATE TABLE statements. This
// scaffold mirrors the JSON shape the core package's MockTRQPService reads
// from data/policies.json and data/revocations.json.
interface AuthorizationRow extends RowDataPacket {
  entity_id: string;
  authority_id: string;
  action: string;
  resource: string;
  context: unknown;
  authorized: number | boolean;
  expires: string | null;
  policy_epoch: string | null;
  evidence: unknown;
  reason: string | null;
  policy_requirements: unknown;
}

interface RecognitionRow extends RowDataPacket {
  authority_id: string;
  recognized_authority_id: string;
  context: unknown;
  recognized: number | boolean;
  expires: string | null;
  policy_epoch: string | null;
  evidence: unknown;
  reason: string | null;
}

interface RevocationRow extends RowDataPacket {
  revoked_entities: unknown;
  policy_epoch: string | null;
  issued_at: string | null;
  channel: string | null;
}

// mysql2 parses native JSON columns into JS values automatically in most
// configurations, but returns a string in others (e.g. TEXT columns storing
// JSON) - parse defensively either way.
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

export interface MySQLPolicyServiceOptions extends MySQLConnectionOptions {
  authorizationsTable?: string;
  recognitionsTable?: string;
  revocationsTable?: string;
}

/**
 * MySQL-backed PolicyService. Authorization/recognition rows are matched by
 * entity/authority/action/resource (or authority/recognized authority) via a
 * SQL WHERE clause, then filtered by context in application code - this
 * deliberately mirrors MockTRQPService's subset-match semantics (every key
 * present in the stored context must match the request's context; the
 * request may carry additional keys) rather than a JSON-equality SQL
 * predicate, which would be both less portable across MySQL versions and
 * order-sensitive.
 */
export class MySQLPolicyService implements PolicyService {
  readonly transportMetadata: FeedTransportMetadata;
  private readonly uri?: string;
  private readonly tables: Required<Pick<MySQLPolicyServiceOptions, "authorizationsTable" | "recognitionsTable" | "revocationsTable">>;

  constructor(options: MySQLPolicyServiceOptions = {}) {
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
    const pool = getMySQLPool(this.uri);
    const [rows] = await pool.query<RevocationRow[]>(`SELECT * FROM ${this.tables.revocationsTable} LIMIT 1`);
    return rows[0];
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

    const pool = getMySQLPool(this.uri);
    const [rows] = await pool.query<AuthorizationRow[]>(
      `SELECT * FROM ${this.tables.authorizationsTable} WHERE entity_id = ? AND authority_id = ? AND action = ? AND resource = ?`,
      [entityId, authorityId, action, resource],
    );
    const match = rows.find((row) => contextMatches(context, parseJsonColumn(row.context, {})));
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
    authorityId: string,
    recognizedAuthorityId: string,
    context: Record<string, unknown>,
  ): Promise<RecognitionResponse> {
    const pool = getMySQLPool(this.uri);
    const [rows] = await pool.query<RecognitionRow[]>(
      `SELECT * FROM ${this.tables.recognitionsTable} WHERE authority_id = ? AND recognized_authority_id = ?`,
      [authorityId, recognizedAuthorityId],
    );
    const match = rows.find((row) => contextMatches(context, parseJsonColumn(row.context, {})));
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

export default MySQLPolicyService;
