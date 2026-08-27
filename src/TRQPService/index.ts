import { readFileSync } from "node:fs";
import { RevocationProcessState, RevocationStatusResponse } from "./revocation/index.js";
import { AuthorizationResponse, createAuthorizationResponse, RecognitionResponse } from "../models.js";
import { EntityStorageState } from "./entityStorage/index.js";
import { RecognitionProcessState } from "./recognition/index.js";
import { createFeedTransportMetadata, type FeedTransportMetadata } from "../transport.js";
import type { PolicyService } from "../policy_service.js";

function parseUtc(ts: string | null | undefined): Date | null {
  if (!ts) return null;
  const date = new Date(ts);
  return Number.isNaN(date.getTime()) ? null : date;
}


export interface TRQPServiceOptions {
    revocationProcessState: RevocationProcessState;
    entityStorageState:EntityStorageState
    recognitionProcessState:RecognitionProcessState
    // How this service is actually reached. Defaults describe a live, TLS-protected
    // network backend - unlike MockTRQPService, which defaults to describing its
    // local JSON file as a full/offline snapshot.
    transportMode?: string;
    transportIntegrity?: string;
    transportAvailable?: boolean;
    transportChannel?: string;
}

export class TRQPService implements PolicyService {
    revocationProcessState: RevocationProcessState;
    entityStorageState:EntityStorageState
    recognitionProcessState:RecognitionProcessState
    readonly transportMetadata: FeedTransportMetadata;
  constructor(options: TRQPServiceOptions) {
    this.revocationProcessState = options.revocationProcessState;
    this.entityStorageState = options.entityStorageState;
    this.recognitionProcessState = options.recognitionProcessState;
    this.transportMetadata = createFeedTransportMetadata({
      mode: options.transportMode ?? "http",
      integrity: options.transportIntegrity ?? "tls",
      available: options.transportAvailable ?? true,
      channel: options.transportChannel ?? "live",
    });
  }

  async feedDescriptorEvidence(): Promise<Record<string, unknown>> {
    // Verifier expects one report per feed, keyed by feed name (see mock_service.ts
    // and feed_descriptor.ts's FeedValidationReport). The policy feed's report comes
    // from entity storage; the revocation feed's report is embedded in revocationStatus()
    // rather than tracked separately, so pull it out from there.
    const [policyEvidence, revocationStatus] = await Promise.all([
      this.entityStorageState.getEvidence(),
      this.revocationProcessState.revocationStatus(),
    ]);
    return {
      policy: policyEvidence,
      revocation: revocationStatus.feed_descriptor,
    };
  }

  async authorization(
    entityId: string,
    authorityId: string,
    action: string,
    resource: string,
    context: Record<string, unknown>,
  ): Promise<AuthorizationResponse> {
   
    // RETURN EARLY IF ENTITY IS REVOKED
    if (await this.revocationProcessState.checkStatus(entityId)) {
      const status = await this.revocationProcessState.revocationStatus();
      return createAuthorizationResponse({
        authorized: false,
        reason: "entity_revoked",
        policy_epoch: status.policy_epoch ?? null,
      });
    }

    return this.entityStorageState.findEntity({
        entityId,
        authorityId,
        action,
        resource,
        context,
    });
  }

  recognition(
    entityId: string,
    authorityId: string,
    action: string,
    resource: string,
    context: Record<string, unknown>,
  ): Promise<RecognitionResponse> {
    return this.recognitionProcessState.checkRecognition({
        entityId,
        authorityId,
        action,
        resource,
        context,
    });
  }

  revocationStatus():  Promise<RevocationStatusResponse> {
    return this.revocationProcessState.revocationStatus();
  }

  async revocationAgeSeconds(): Promise<number | null> {
    const status = await this.revocationProcessState.revocationStatus();
    if (!status.issued_at) return null;
    const issued = parseUtc(status.issued_at);
    if (issued === null) return null;
    const deltaSeconds = (Date.now() - issued.getTime()) / 1000;
    return Math.max(Math.trunc(deltaSeconds), 0);
  }
}
