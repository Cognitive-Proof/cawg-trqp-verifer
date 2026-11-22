/** What a grant authorizes: TRQP's (authority_id, action, resource) triple. */
export interface Permission {
  authority_id: string;
  action: string;
  resource: string;
}

/** Self-reported details an applicant attaches to a request. */
export interface Applicant {
  name?: string;
  organization?: string;
  email?: string;
  note?: string;
}

export type RequestStatus = "pending" | "approved" | "rejected";

/** A request by `entity_id` to be granted a permission. */
export interface AccessRequest extends Permission {
  id: string;
  entity_id: string;
  context: Record<string, unknown>;
  applicant: Applicant;
  /** Evidence gathered when the request was accepted (proof of possession, checks run). */
  evidence: string[];
  status: RequestStatus;
  created_at: string;
  decided_at: string | null;
  decided_by: string | null;
  decision_note: string | null;
  grant_id: string | null;
}

/**
 * A grant. It keeps the authorization document shape the MongoDB plugin's
 * MongoPolicyService reads (entity_id, authority_id, action, resource,
 * context, authorized, expires, policy_epoch, evidence, reason), plus the
 * history needed to answer "was this entity authorized at time T?".
 */
export interface Grant extends Permission {
  id: string;
  entity_id: string;
  context: Record<string, unknown>;
  authorized: boolean;
  expires: string | null;
  policy_epoch: string | null;
  evidence: string[];
  reason: string | null;
  granted_at: string;
  granted_by: string;
  revoked_at: string | null;
  revoked_by: string | null;
  request_id: string | null;
}

export interface Challenge {
  id: string;
  expires_at: string;
}

export type AuditAction = "request.created" | "request.approved" | "request.rejected" | "grant.created" | "grant.revoked";

export interface AuditEvent {
  at: string;
  actor: string;
  action: AuditAction;
  subject_id: string;
  entity_id: string;
  detail: Record<string, unknown>;
}
