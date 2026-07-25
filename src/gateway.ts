import type { MockTRQPService } from "./mock_service.js";
import { createFeedTransportMetadata, type FeedTransportMetadata } from "./transport.js";
import type { AuthorizationResponse, RecognitionResponse } from "./models.js";

export interface AuthorityRoute {
  service: MockTRQPService;
  route_label?: string;
}

export interface GatewayOptions {
  gatewayId?: string;
  routeLabel?: string;
  authorityRoutes?: Record<string, AuthorityRoute>;
  transportIntegrity?: string;
}

/**
 * Remote policy mediation component for verifier-side trust orchestration.
 * The gateway supports deterministic route selection and exports route/feed
 * evidence so mediated authorization can be replayed and audited.
 */
export class TrustGateway {
  readonly service: MockTRQPService | null;
  readonly gatewayId: string;
  readonly routeLabel: string;
  readonly authorityRoutes: Record<string, AuthorityRoute>;
  readonly transportMetadata: FeedTransportMetadata;

  constructor(service: MockTRQPService | null = null, options: GatewayOptions = {}) {
    this.service = service;
    this.gatewayId = options.gatewayId ?? "gateway:default";
    this.routeLabel = options.routeLabel ?? "default";
    this.authorityRoutes = options.authorityRoutes ?? {};
    this.transportMetadata = createFeedTransportMetadata({
      mode: "gateway",
      integrity: options.transportIntegrity ?? "signed",
      available: service !== null || Object.keys(this.authorityRoutes).length > 0,
      channel: "mediated",
    });
  }

  private resolveRoute(authorityId: string): [MockTRQPService, string] {
    const route = this.authorityRoutes[authorityId];
    if (route !== undefined) {
      return [route.service, route.route_label ?? authorityId];
    }
    if (this.service === null) {
      throw new Error(`No policy route configured for authority ${authorityId}`);
    }
    return [this.service, this.routeLabel];
  }

  private mediation(
    service: MockTRQPService,
    routeLabel: string,
    authorityId: string,
    decisionType: string,
  ): Record<string, unknown> {
    const feed = (service.feedDescriptorEvidence().policy as Record<string, unknown> | undefined) ?? {};
    return {
      gateway_id: this.gatewayId,
      route_label: routeLabel,
      mode: "remote_policy_mediation",
      target_authority_id: authorityId,
      decision_type: decisionType,
      route_attested: Boolean(feed.route_attested ?? false),
      feed_descriptor: feed,
    };
  }

  authorization(
    entityId: string,
    authorityId: string,
    action: string,
    resource: string,
    context: Record<string, unknown>,
  ): [Record<string, unknown>, Record<string, unknown>] {
    const [service, routeLabel] = this.resolveRoute(authorityId);
    const response = service.authorization(entityId, authorityId, action, resource, context);
    return [asDict(response), this.mediation(service, routeLabel, authorityId, "authorization")];
  }

  recognition(
    authorityId: string,
    recognizedAuthorityId: string,
    context: Record<string, unknown>,
  ): [Record<string, unknown>, Record<string, unknown>] {
    const [service, routeLabel] = this.resolveRoute(authorityId);
    const response = service.recognition(authorityId, recognizedAuthorityId, context);
    return [asDict(response), this.mediation(service, routeLabel, authorityId, "recognition")];
  }
}

function asDict(response: AuthorizationResponse | RecognitionResponse): Record<string, unknown> {
  return { ...response } as unknown as Record<string, unknown>;
}
