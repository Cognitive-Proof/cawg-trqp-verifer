import type { PolicyService } from "./policy_service.js";
import { createFeedTransportMetadata, type FeedTransportMetadata } from "./transport.js";
import type { AuthorizationResponse, RecognitionResponse } from "./models.js";

export interface AuthorityRoute {
  service: PolicyService;
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
  readonly service: PolicyService | null;
  readonly gatewayId: string;
  readonly routeLabel: string;
  readonly authorityRoutes: Record<string, AuthorityRoute>;
  readonly transportMetadata: FeedTransportMetadata;

  constructor(service: PolicyService | null = null, options: GatewayOptions = {}) {
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

  private resolveRoute(authorityId: string): [PolicyService, string] {
    const route = this.authorityRoutes[authorityId];
    if (route !== undefined) {
      return [route.service, route.route_label ?? authorityId];
    }
    if (this.service === null) {
      throw new Error(`No policy route configured for authority ${authorityId}`);
    }
    return [this.service, this.routeLabel];
  }

  private async mediation(
    service: PolicyService,
    routeLabel: string,
    authorityId: string,
    decisionType: string,
  ): Promise<Record<string, unknown>> {
    const feedEvidence = await service.feedDescriptorEvidence();
    const feed = (feedEvidence.policy as Record<string, unknown> | undefined) ?? {};
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

  async authorization(
    entityId: string,
    authorityId: string,
    action: string,
    resource: string,
    context: Record<string, unknown>,
  ): Promise<[Record<string, unknown>, Record<string, unknown>]> {
    const [service, routeLabel] = this.resolveRoute(authorityId);
    const response = await service.authorization(entityId, authorityId, action, resource, context);
    return [asDict(response), await this.mediation(service, routeLabel, authorityId, "authorization")];
  }

  /**
   * routeAuthorityId picks which registry answers the query (mirroring
   * authorization's routing, so a multi-authority mesh keyed by the
   * request's home authority still resolves correctly); authorityId is the
   * query's own "is this authority recognized..." subject (TRQP v2 recognition
   * is often checking an issuer's standing, so the two can legitimately
   * differ from each other).
   */
  async recognition(
    routeAuthorityId: string,
    entityId: string,
    authorityId: string,
    action: string,
    resource: string,
    context: Record<string, unknown>,
  ): Promise<[Record<string, unknown>, Record<string, unknown>]> {
    const [service, routeLabel] = this.resolveRoute(routeAuthorityId);
    const response = await service.recognition(entityId, authorityId, action, resource, context);
    return [asDict(response), await this.mediation(service, routeLabel, routeAuthorityId, "recognition")];
  }
}

function asDict(response: AuthorizationResponse | RecognitionResponse): Record<string, unknown> {
  return { ...response } as unknown as Record<string, unknown>;
}
