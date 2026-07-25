export interface VerificationRequest {
  asset_id: string;
  integrity_ok: boolean;
  entity_id: string;
  authority_id: string;
  issuer_id: string | null;
  action: string;
  resource: string;
  context: Record<string, unknown>;
  process_evidence: Record<string, unknown> | null;
}

export function createVerificationRequest(
  fields: Partial<VerificationRequest> &
    Pick<VerificationRequest, "asset_id" | "integrity_ok" | "entity_id" | "authority_id" | "action" | "resource">,
): VerificationRequest {
  return {
    issuer_id: null,
    context: {},
    process_evidence: null,
    ...fields,
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

export interface VerificationResult {
  asset_integrity: string;
  assertion_binding: string;
  issuer_recognition: string;
  actor_authorization: string;
  process_integrity: string;
  policy_freshness: string;
  verification_mode: string;
  trust_outcome: string;
  process_appraisal: Record<string, unknown>;
  policy_evidence: Record<string, unknown>;
  gateway_mediation: Record<string, unknown>;
  explanations: string[];
}

export function createVerificationResult(
  fields: Partial<VerificationResult> &
    Pick<
      VerificationResult,
      | "asset_integrity"
      | "assertion_binding"
      | "issuer_recognition"
      | "actor_authorization"
      | "process_integrity"
      | "policy_freshness"
      | "verification_mode"
      | "trust_outcome"
    >,
): VerificationResult {
  return {
    process_appraisal: {},
    policy_evidence: {},
    gateway_mediation: {},
    explanations: [],
    ...fields,
  };
}

export function verificationResultToDict(result: VerificationResult): Record<string, unknown> {
  return { ...result };
}
