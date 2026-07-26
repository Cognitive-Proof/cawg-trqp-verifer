import type { AuthorizationResponse, RecognitionResponse } from "./models.js";
import type { FeedTransportMetadata } from "./transport.js";

/**
 * Shared contract for anything that can answer TRQP policy questions -
 * whether that's an in-memory mock reading local JSON (MockTRQPService) or a
 * real network-backed client (TRQPService). Verifier, TrustGateway, and
 * HTTPTRQPService depend on this instead of a concrete class so either can be
 * plugged in.
 *
 * transportMetadata is a plain synchronous property (not a lookup) because it
 * describes how this service is configured to be reached, not a live result.
 * Everything else does real work (network calls for a real backend) and is
 * async even though MockTRQPService's implementation resolves instantly.
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
