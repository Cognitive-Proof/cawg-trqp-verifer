import { existsSync, readFileSync } from "node:fs";

export const PROCESS_ASSERTION_LABELS = new Set([
  "cawg.process",
  "cawg.process.proof",
  "org.cawg.process",
  "org.contentauthorship.process",
]);

export interface ManifestSignal {
  actor_id: string;
  issuer_id: string | null;
  credential_type: string | null;
  assertions: Record<string, unknown>[];
  provenance_chain: string[];
  integrity_status: string;
  action: string | null;
  resource: string | null;
  context: Record<string, unknown>;
  process_evidence: Record<string, unknown> | null;
  parser_mode: string;
  raw_manifest: Record<string, unknown>;
}

function createManifestSignal(
  fields: Partial<ManifestSignal> & Pick<ManifestSignal, "actor_id">,
): ManifestSignal {
  return {
    issuer_id: null,
    credential_type: null,
    assertions: [],
    provenance_chain: [],
    integrity_status: "unknown",
    action: null,
    resource: null,
    context: {},
    process_evidence: null,
    parser_mode: "unknown",
    raw_manifest: {},
    ...fields,
  };
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

export class CAWGManifestParser {
  static readonly FIXTURE_MODEL_VERSION = "0.3";

  static parseFile(manifestPath: string): ManifestSignal {
    if (!existsSync(manifestPath)) {
      throw new Error(`Manifest not found: ${manifestPath}`);
    }
    let data: Record<string, unknown>;
    try {
      data = JSON.parse(readFileSync(manifestPath, "utf-8"));
    } catch (exc) {
      throw new Error(`Invalid JSON in manifest: ${(exc as Error).message}`);
    }
    return CAWGManifestParser.parseDict(data);
  }

  static parseFixture(fixturePath: string): ManifestSignal {
    return CAWGManifestParser.parseFile(fixturePath);
  }

  static parseDict(manifestData: Record<string, unknown>): ManifestSignal {
    if ("manifest_store" in manifestData) {
      return CAWGManifestParser.extractC2paManifest(manifestData);
    }
    return CAWGManifestParser.extractFixtureManifest(manifestData);
  }

  private static extractFixtureManifest(manifestData: Record<string, unknown>): ManifestSignal {
    const issuer = asRecord(manifestData.issuer);
    const actor = asRecord(manifestData.actor);
    const assertion = asRecord(manifestData.assertion);
    const context: Record<string, unknown> = { ...asRecord(manifestData.context) };
    const processEvidence =
      manifestData.process_evidence !== null && typeof manifestData.process_evidence === "object"
        ? (manifestData.process_evidence as Record<string, unknown>)
        : null;
    const credentialType = (manifestData.credential_type as string | undefined) ?? (issuer.credential_type as string | undefined);
    if (credentialType && context.credential_type === undefined) {
      context.credential_type = credentialType;
    }

    let actorId: string;
    let issuerId: string | null;
    let action: string | null;
    let resource: string | null;

    if ("actor_id" in manifestData) {
      actorId = (manifestData.actor_id as string | undefined) ?? "unknown";
      issuerId = (manifestData.issuer_id as string | undefined) ?? null;
      action = (manifestData.action as string | undefined) ?? null;
      resource = (manifestData.resource as string | undefined) ?? null;
      if (action === null || action === undefined) {
        action = (assertion.action as string | undefined) ?? null;
      }
      if (resource === null || resource === undefined) {
        resource = (assertion.resource as string | undefined) ?? null;
      }
    } else {
      actorId = (actor.entity_id as string | undefined) ?? "unknown";
      issuerId = (issuer.issuer_id as string | undefined) ?? null;
      action = (assertion.action as string | undefined) ?? null;
      resource = (assertion.resource as string | undefined) ?? null;
    }

    const assertions: Record<string, unknown>[] = [];
    if (Object.keys(assertion).length) {
      assertions.push({ label: "cawg.assertion", data: assertion });
    }
    assertions.push(...((manifestData.assertions as Record<string, unknown>[] | undefined) ?? []));

    const integrityStatus =
      (manifestData.integrity_status as string | undefined) ?? (manifestData.integrity_ok ? "verified" : "unknown");

    return createManifestSignal({
      actor_id: actorId,
      issuer_id: issuerId,
      credential_type: credentialType ?? null,
      assertions,
      provenance_chain: (manifestData.provenance_chain as string[] | undefined) ?? [],
      integrity_status: integrityStatus,
      action,
      resource,
      context,
      process_evidence: processEvidence,
      parser_mode: "fixture",
      raw_manifest: manifestData,
    });
  }

  private static extractC2paManifest(manifestData: Record<string, unknown>): ManifestSignal {
    const store = asRecord(manifestData.manifest_store);
    const manifests = asRecord(store.manifests);
    const activeManifestId = store.active_manifest as string | undefined;
    const activeManifest = activeManifestId ? asRecord(manifests[activeManifestId]) : {};

    let actorId = "unknown";
    let issuerId: string | null = null;
    let credentialType: string | null = null;
    let action: string | null = null;
    let resource: string | null = null;
    const context: Record<string, unknown> = {};
    const assertions: Record<string, unknown>[] = [];
    const provenanceChain: string[] = [];
    let processEvidence: Record<string, unknown> | null = null;

    const signatureInfo = asRecord(activeManifest.signature_info);
    if (Object.keys(signatureInfo).length) {
      issuerId = (signatureInfo.issuer as string | undefined) ?? (signatureInfo.signer as string | undefined) ?? null;
    }

    for (const assertionEntry of (activeManifest.assertions as Record<string, unknown>[] | undefined) ?? []) {
      if (typeof assertionEntry !== "object" || assertionEntry === null) continue;
      const label = (assertionEntry.label as string | undefined) ?? "unlabeled";
      const data = asRecord(assertionEntry.data);
      assertions.push({ label, data });

      if (
        ["cawg.actions", "cawg.identity", "org.contentauthorship.identity"].includes(label) &&
        Object.keys(data).length
      ) {
        const actor = asRecord(data.actor);
        actorId = (actor.id as string | undefined) ?? (actor.entity_id as string | undefined) ?? (data.actor_id as string | undefined) ?? actorId;
        issuerId = (data.issuer_id as string | undefined) ?? issuerId;
        credentialType = (data.credential_type as string | undefined) ?? credentialType;
        action = (data.action as string | undefined) ?? action;
        resource = (data.resource as string | undefined) ?? resource;
        for (const key of ["jurisdiction", "risk_tier", "content_type", "credential_type"]) {
          if (key in data) {
            context[key] = data[key];
          }
        }
      }

      if (label === "c2pa.actions" && Object.keys(data).length && action === null) {
        const actions = (data.actions as Record<string, unknown>[] | undefined) ?? [];
        if (actions.length && typeof actions[0] === "object") {
          action = (actions[0].action as string | undefined) ?? action;
          resource = (actions[0].resource as string | undefined) ?? resource;
        }
      }

      if ((PROCESS_ASSERTION_LABELS.has(label) || label.includes("process")) && Object.keys(data).length) {
        processEvidence = { ...data };
        if (context.process_type === undefined) {
          context.process_type = data.process_type ?? "unspecified";
        }
      }
    }

    for (const ingredient of (activeManifest.ingredients as Record<string, unknown>[] | undefined) ?? []) {
      if (typeof ingredient === "object" && ingredient !== null) {
        const title = (ingredient.title as string | undefined) ?? (ingredient.instance_id as string | undefined) ?? (ingredient.document_id as string | undefined);
        if (title) provenanceChain.push(title);
      }
    }

    for (const parent of (activeManifest.parent_claims as Record<string, unknown>[] | undefined) ?? []) {
      if (typeof parent === "object" && parent !== null) {
        const parentId = (parent.manifest as string | undefined) ?? (parent.claim as string | undefined) ?? (parent.title as string | undefined);
        if (parentId) provenanceChain.push(parentId);
      }
    }

    if (credentialType && context.credential_type === undefined) {
      context.credential_type = credentialType;
    }

    const integrityStatus =
      (activeManifest.integrity_status as string | undefined) ?? (manifestData.integrity_status as string | undefined) ?? "verified";

    return createManifestSignal({
      actor_id: actorId,
      issuer_id: issuerId,
      credential_type: credentialType,
      assertions,
      provenance_chain: provenanceChain,
      integrity_status: integrityStatus,
      action,
      resource,
      context,
      process_evidence: processEvidence,
      parser_mode: "c2pa_json",
      raw_manifest: manifestData,
    });
  }

  static validateFixture(fixturePath: string): Record<string, unknown> {
    const signal = CAWGManifestParser.parseFile(fixturePath);
    return {
      valid: signal.actor_id !== "unknown" && Boolean(signal.action) && Boolean(signal.resource),
      parser_mode: signal.parser_mode,
      has_issuer_id: signal.issuer_id !== null,
      has_assertions: signal.assertions.length > 0,
      has_credential_type: signal.credential_type !== null,
      has_process_evidence: signal.process_evidence !== null,
    };
  }
}
