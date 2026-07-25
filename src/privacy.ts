export interface PrivacyProfile {
  id: string;
  include_raw_request: boolean;
  include_process_evidence: boolean;
  pseudonymize_identifiers: boolean;
  retention_days: number;
  access_scope: string;
}

export const BUILTIN_PRIVACY_PROFILES: Record<string, PrivacyProfile> = {
  minimal_receipt: {
    id: "minimal_receipt",
    include_raw_request: false,
    include_process_evidence: false,
    pseudonymize_identifiers: true,
    retention_days: 30,
    access_scope: "trqp.receipt.read",
  },
  replay_bundle: {
    id: "replay_bundle",
    include_raw_request: true,
    include_process_evidence: true,
    pseudonymize_identifiers: false,
    retention_days: 90,
    access_scope: "trqp.audit.export",
  },
  regulated_evidence: {
    id: "regulated_evidence",
    include_raw_request: true,
    include_process_evidence: true,
    pseudonymize_identifiers: false,
    retention_days: 365,
    access_scope: "trqp.audit.regulated",
  },
};

export function loadPrivacyProfile(value: string | PrivacyProfile | null | undefined): PrivacyProfile {
  if (value !== null && typeof value === "object") {
    return value;
  }
  const key = value || "minimal_receipt";
  const profile = BUILTIN_PRIVACY_PROFILES[key];
  if (!profile) {
    throw new Error(`unknown privacy profile: ${key}`);
  }
  return profile;
}

export function validateContext(context: Record<string, unknown>, allowedFields?: Set<string> | null): void {
  if (!allowedFields) {
    return;
  }
  const unexpected = Object.keys(context)
    .filter((key) => !allowedFields.has(key))
    .sort();
  if (unexpected.length) {
    throw new Error(`context contains fields not allowed by the active context profile: ${unexpected.join(", ")}`);
  }
}
