import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv2020 } from "ajv/dist/2020.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = path.resolve(__dirname, "..");
const SCHEMA_PATH = path.join(PACKAGE_ROOT, "schemas", "verification-profile.schema.json");
const BUILTIN_PROFILE_DIR = path.join(PACKAGE_ROOT, "profiles");
const BUILTIN_OVERLAY_DIR = path.join(BUILTIN_PROFILE_DIR, "overlays");
export const BUILTIN_PROFILE_NAMES = new Set(["edge", "standard", "high_assurance"]);

function displayPath(filePath: string): string {
  const resolved = path.resolve(filePath);
  const relative = path.relative(PACKAGE_ROOT, resolved);
  return relative.startsWith("..") ? filePath : relative;
}

export class VerificationProfileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerificationProfileError";
  }
}

export const DEFAULT_CONTROLS: Record<string, any> = {
  authority: {
    trust_anchors_required: false,
    allow_untrusted: true,
  },
  freshness: {
    max_age_seconds: 86400,
    require_live: false,
  },
  revocation: {
    mode: "snapshot",
    hard_fail: false,
    max_age_seconds: 86400,
    enforcement: "warn",
    delta_channel_required: false,
  },
  failure: {
    network_failure: "fail_open",
    policy_unavailable: "fail_open",
  },
  evidence: {
    emit_audit_bundle: true,
    require_attestation: false,
    require_feed_descriptors: false,
  },
  descriptor_policy: {
    policy: "observe",
    revocation: "observe",
    snapshot: "observe",
    gateway_route: "observe",
  },
  transport: {
    mode: "local",
    integrity: "none",
    availability_requirement: "best_effort",
  },
  determinism: {
    replayable: true,
    require_pinned_feeds: false,
  },
};

export interface VerificationProfile {
  id: string;
  base_profile: string;
  controls: Record<string, any>;
  overlays: string[];
  source: string;
}

export function verificationProfileToDict(profile: VerificationProfile): Record<string, unknown> {
  return {
    id: profile.id,
    base_profile: profile.base_profile,
    controls: deepClone(profile.controls),
    overlays: [...profile.overlays],
    source: profile.source,
  };
}

export interface VerificationOverlay {
  id: string;
  description: string;
  controls: Record<string, any>;
  source: string;
}

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value));
}

function loadJson(filePath: string): Record<string, any> {
  return JSON.parse(readFileSync(filePath, "utf-8"));
}

function deepMerge(base: Record<string, any>, patch: Record<string, any>): Record<string, any> {
  const merged = deepClone(base);
  for (const [key, value] of Object.entries(patch)) {
    if (value !== null && typeof value === "object" && !Array.isArray(value) && typeof merged[key] === "object" && merged[key] !== null && !Array.isArray(merged[key])) {
      merged[key] = deepMerge(merged[key], value);
    } else {
      merged[key] = deepClone(value);
    }
  }
  return merged;
}

let cachedValidator: import("ajv").ValidateFunction | undefined;

function getValidator(): import("ajv").ValidateFunction {
  if (!cachedValidator) {
    const ajv = new Ajv2020({ allErrors: true, strict: false });
    const schema = loadJson(SCHEMA_PATH);
    cachedValidator = ajv.compile(schema);
  }
  return cachedValidator;
}

export function validateProfilePayload(payload: Record<string, unknown>): void {
  const validate = getValidator();
  const valid = validate(payload);
  if (!valid) {
    const errors = [...(validate.errors ?? [])].sort((a, b) => (a.instancePath ?? "").localeCompare(b.instancePath ?? ""));
    const message = errors
      .map((err) => `${err.instancePath.replace(/^\//, "") || "<root>"}: ${err.message}`)
      .join("; ");
    throw new VerificationProfileError(message);
  }
}

export function builtinProfilePath(name: string): string {
  return path.join(BUILTIN_PROFILE_DIR, `${name}.json`);
}

export function builtinOverlayPath(name: string): string {
  return path.join(BUILTIN_OVERLAY_DIR, `${name}.json`);
}

export function loadOverlay(pathOrName: string): VerificationOverlay {
  let overlayPath = pathOrName;
  if (!existsSync(overlayPath)) {
    overlayPath = builtinOverlayPath(pathOrName);
  }
  if (!existsSync(overlayPath)) {
    throw new VerificationProfileError(`Unknown overlay: ${pathOrName}`);
  }
  const data = loadJson(overlayPath);
  if (!("id" in data) || !("controls" in data)) {
    throw new VerificationProfileError(`Overlay ${overlayPath} must include id and controls`);
  }
  return {
    id: data.id,
    description: data.description ?? "",
    controls: data.controls,
    source: displayPath(overlayPath),
  };
}

export type ProfileInput = string | Record<string, unknown> | VerificationProfile;

export function loadProfile(profile: ProfileInput = "standard", overlays: string[] | null = null): VerificationProfile {
  // Note: an already-resolved VerificationProfile and a plain inline-profile
  // object are structurally indistinguishable in TS (no nominal typing), so
  // both flow through the same merge path below. Re-merging DEFAULT_CONTROLS
  // into an already-fully-populated controls object is idempotent, so this
  // is safe and produces the same result as the Python fast path.
  if (typeof profile === "object" && profile !== null) {
    const payload: Record<string, any> = deepClone(profile);
    payload.controls = deepMerge(DEFAULT_CONTROLS, payload.controls ?? {});
    payload.overlays = payload.overlays ?? [];
    payload.source = payload.source ?? "inline";
    validateProfilePayload(payload);
    const resolved: VerificationProfile = {
      id: payload.id,
      base_profile: payload.base_profile,
      controls: payload.controls,
      overlays: payload.overlays ?? [],
      source: payload.source ?? "inline",
    };
    if (overlays && overlays.length) {
      return applyOverlays(resolved, overlays);
    }
    return resolved;
  }

  let profilePath = String(profile);
  if (!existsSync(profilePath)) {
    profilePath = builtinProfilePath(String(profile));
  }
  if (!existsSync(profilePath)) {
    throw new VerificationProfileError(`Unknown profile: ${profile}`);
  }

  const data = loadJson(profilePath);
  const payload = {
    id: data.id,
    base_profile: data.base_profile,
    controls: deepMerge(DEFAULT_CONTROLS, data.controls ?? {}),
    overlays: data.overlays ?? [],
    source: displayPath(profilePath),
  };
  validateProfilePayload(payload);
  const resolved: VerificationProfile = {
    id: payload.id,
    base_profile: payload.base_profile,
    controls: payload.controls,
    overlays: payload.overlays,
    source: payload.source,
  };
  if (overlays && overlays.length) {
    return applyOverlays(resolved, overlays);
  }
  return resolved;
}

/** Load a profile from an API boundary without resolving filesystem paths. */
export function loadApiProfile(profile: ProfileInput = "standard", overlays: string[] | null = null): VerificationProfile {
  if (typeof profile === "string" && !BUILTIN_PROFILE_NAMES.has(profile)) {
    throw new VerificationProfileError(`API profile must be one of ${[...BUILTIN_PROFILE_NAMES].sort().join(", ")}`);
  }
  if (overlays && overlays.length) {
    const unknown = overlays.filter((overlay) => path.basename(overlay) !== overlay);
    if (unknown.length) {
      throw new VerificationProfileError("API overlays must use built-in overlay names, not filesystem paths");
    }
  }
  return loadProfile(profile, overlays);
}

export function applyOverlays(profile: VerificationProfile, overlays: string[]): VerificationProfile {
  let controls = deepClone(profile.controls);
  const overlayIds = [...profile.overlays];
  for (const overlayRef of overlays) {
    const overlay = loadOverlay(overlayRef);
    controls = deepMerge(controls, overlay.controls);
    overlayIds.push(overlay.id);
  }
  const payload = {
    id: profile.id,
    base_profile: profile.base_profile,
    controls,
    overlays: overlayIds,
    source: profile.source,
  };
  validateProfilePayload(payload);
  return {
    id: payload.id,
    base_profile: payload.base_profile,
    controls: payload.controls,
    overlays: overlayIds,
    source: payload.source,
  };
}
