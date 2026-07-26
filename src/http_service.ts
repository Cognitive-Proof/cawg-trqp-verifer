import express, { type Express, type Request, type Response, type NextFunction } from "express";
import { auditBundleToDict, buildAuditBundle } from "./audit.js";
import { TTLCache, type DecisionCache } from "./DecisionCache/index.js";
import { TrustGateway } from "./gateway.js";
import type { PolicyService } from "./policy_service.js";
import { createVerificationRequest, type AuthorizationResponse, type RecognitionResponse } from "./models.js";
import { VerificationProfileError, loadApiProfile, type VerificationProfile } from "./profile.js";
import { loadPrivacyProfile } from "./privacy.js";
import { requireScope, PermissionError } from "./access_control.js";
import { Verifier } from "./verifier.js";

const MAX_REQUEST_BYTES = 64 * 1024;

export interface HTTPTRQPServiceOptions {
  gatewayId?: string;
  routeLabel?: string;
  cache?: DecisionCache<Record<string, unknown>>;
}

/** Wraps any async handler so a rejected promise reaches Express's error middleware
 * instead of becoming an unhandled rejection (Express 4 doesn't await handlers itself,
 * so a real, fallible PolicyService backend needs this to fail gracefully). */
function asyncHandler(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res).catch(next);
  };
}

/** Express wrapper for TRQP policy service and verifier patterns. */
export class HTTPTRQPService {
  readonly service: PolicyService;
  readonly gateway: TrustGateway;
  readonly cache: DecisionCache<Record<string, unknown>>;
  readonly verifier: Verifier;
  readonly gatewayVerifier: Verifier;
  readonly app: Express;

  constructor(service: PolicyService, options: HTTPTRQPServiceOptions = {}) {
    this.service = service;
    this.gateway = new TrustGateway(this.service, {
      gatewayId: options.gatewayId ?? "gateway:http",
      routeLabel: options.routeLabel ?? "http-pattern",
    });
    // Long-lived L1 cache and verifier instances preserve cache semantics across
    // HTTP requests. Production deployments can replace this adapter with a
    // shared DecisionCache implementation.
    this.cache = options.cache ?? new TTLCache<Record<string, unknown>>(4096);
    this.verifier = new Verifier({ service: this.service, cache: this.cache });
    this.gatewayVerifier = new Verifier({ service: this.service, gateway: this.gateway, cache: this.cache });
    this.app = express();
    this.app.use(express.json({ limit: MAX_REQUEST_BYTES, strict: true }));
    this.registerRoutes();
  }

  private registerRoutes(): void {
    const app = this.app;

    app.use((err: unknown, _req: Request, res: Response, next: (err?: unknown) => void) => {
      if (err && typeof err === "object" && "type" in err && (err as { type?: string }).type === "entity.too.large") {
        res
          .status(413)
          .json({ error: "request_too_large", message: `Request body exceeds ${MAX_REQUEST_BYTES} bytes` });
        return;
      }
      if (err) {
        res.status(400).json({ error: "invalid_request", message: "Request body must be valid JSON" });
        return;
      }
      next();
    });

    app.get("/health", (_req, res) => {
      res.status(200).json({
        status: "healthy",
        capabilities: ["authorization", "recognition", "verify", "audit_bundle", "gateway"],
      });
    });

    app.post(
      "/trqp/authorization",
      asyncHandler(async (req, res) => {
        const { data, error } = this.jsonBody(req, res);
        if (error) return;
        const required = ["entity_id", "authority_id", "action", "resource"];
        const missing = required.filter((f) => !(f in data));
        if (missing.length) {
          res.status(400).json({ error: "invalid_request", message: `Missing fields: ${missing.join(", ")}` });
          return;
        }
        if (this.requireStrings(res, data, required)) return;
        const result = await this.service.authorization(
          data.entity_id,
          data.authority_id,
          data.action,
          data.resource,
          data.context ?? {},
        );
        res.status(200).json(this.serializeResponse(result));
      }),
    );

    app.post(
      "/trqp/recognition",
      asyncHandler(async (req, res) => {
        const { data, error } = this.jsonBody(req, res);
        if (error) return;
        const required = ["authority_id", "recognized_authority_id"];
        const missing = required.filter((f) => !(f in data));
        if (missing.length) {
          res.status(400).json({ error: "invalid_request", message: `Missing fields: ${missing.join(", ")}` });
          return;
        }
        if (this.requireStrings(res, data, required)) return;
        const result = await this.service.recognition(data.authority_id, data.recognized_authority_id, data.context ?? {});
        res.status(200).json(this.serializeResponse(result));
      }),
    );

    app.post(
      "/trqp/gateway/authorization",
      asyncHandler(async (req, res) => {
        const { data, error } = this.jsonBody(req, res);
        if (error) return;
        const required = ["entity_id", "authority_id", "action", "resource"];
        const missing = required.filter((f) => !(f in data));
        if (missing.length) {
          res.status(400).json({ error: "invalid_request", message: `Missing fields: ${missing.join(", ")}` });
          return;
        }
        if (this.requireStrings(res, data, required)) return;
        const [result, mediation] = await this.gateway.authorization(
          data.entity_id,
          data.authority_id,
          data.action,
          data.resource,
          data.context ?? {},
        );
        res.status(200).json({ authorization: result, gateway_mediation: mediation });
      }),
    );

    app.post(
      "/trqp/verify",
      asyncHandler(async (req, res) => {
        const { data, error } = this.jsonBody(req, res);
        if (error) return;
        let request;
        let profile: VerificationProfile;
        try {
          request = createVerificationRequest(this.verificationRequestFields(data));
          profile = this.resolveApiProfile(data);
        } catch (exc) {
          res.status(400).json({ error: "invalid_request", message: (exc as Error).message });
          return;
        }
        const verifier = data.use_gateway ? this.gatewayVerifier : this.verifier;
        const result = await verifier.verify(request, profile);
        this.emitAuditEvent("verify", profile, Boolean(data.use_gateway), result as unknown as Record<string, unknown>);
        res.status(200).json(result);
      }),
    );

    app.post(
      "/trqp/audit-bundle",
      asyncHandler(async (req, res) => {
        const { data, error } = this.jsonBody(req, res);
        if (error) return;
        let request;
        let profile: VerificationProfile;
        try {
          request = createVerificationRequest(this.verificationRequestFields(data));
          profile = this.resolveApiProfile(data);
        } catch (exc) {
          res.status(400).json({ error: "invalid_request", message: (exc as Error).message });
          return;
        }
        const useGateway = Boolean(data.use_gateway);
        const verifier = useGateway ? this.gatewayVerifier : this.verifier;
        const result = await verifier.verify(request, profile);
        this.emitAuditEvent("audit_bundle", profile, useGateway, result as unknown as Record<string, unknown>);
        const privacyName = data.privacy_profile ?? "minimal_receipt";
        try {
          const privacyProfile = loadPrivacyProfile(privacyName);
          const scopes = new Set(
            (String(req.headers["x-trqp-scopes"] ?? ""))
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean),
          );
          if (privacyProfile.include_raw_request) {
            requireScope(scopes, privacyProfile.access_scope);
          }
          const bundle = buildAuditBundle(request, result, {
            profile,
            useGateway,
            privacyProfile: privacyProfile,
          });
          res.status(200).json(auditBundleToDict(bundle));
        } catch (exc) {
          if (exc instanceof PermissionError) {
            res.status(403).json({ error: "forbidden", message: exc.message });
          } else {
            res.status(400).json({ error: "invalid_request", message: (exc as Error).message });
          }
        }
      }),
    );

    // Catch-all for errors forwarded by asyncHandler (e.g. a real PolicyService
    // backend failing a network call) that weren't already handled above.
    app.use((err: unknown, _req: Request, res: Response, next: NextFunction) => {
      if (res.headersSent) {
        next(err);
        return;
      }
      console.error("cawg_trqp_http_error", err);
      res.status(502).json({ error: "upstream_unavailable", message: "The policy service could not complete the request" });
    });
  }

  private jsonBody(req: Request, res: Response): { data: Record<string, any>; error: boolean } {
    if (!req.is("application/json")) {
      res.status(415).json({ error: "invalid_request", message: "Request content type must be application/json" });
      return { data: {}, error: true };
    }
    const data = req.body;
    if (typeof data !== "object" || data === null || Array.isArray(data)) {
      res.status(400).json({ error: "invalid_request", message: "Request body must be a JSON object" });
      return { data: {}, error: true };
    }
    return { data, error: false };
  }

  private requireStrings(res: Response, data: Record<string, any>, fields: string[]): boolean {
    const invalid = fields.filter((field) => typeof data[field] !== "string" || !data[field]);
    if (invalid.length) {
      res.status(400).json({ error: "invalid_request", message: `Fields must be non-empty strings: ${invalid.join(", ")}` });
      return true;
    }
    if ("context" in data && (typeof data.context !== "object" || data.context === null || Array.isArray(data.context))) {
      res.status(400).json({ error: "invalid_request", message: "context must be a JSON object" });
      return true;
    }
    return false;
  }

  private resolveApiProfile(data: Record<string, any>): VerificationProfile {
    const overlays = data.overlays ?? [];
    if (overlays.length && !Array.isArray(overlays)) {
      throw new VerificationProfileError("overlays must be a list of built-in overlay names");
    }
    return loadApiProfile(data.profile ?? "standard", overlays);
  }

  private verificationRequestFields(
    data: Record<string, any>,
  ): Partial<import("./models.js").VerificationRequest> &
    Pick<import("./models.js").VerificationRequest, "asset_id" | "integrity_ok" | "entity_id" | "authority_id" | "action" | "resource"> {
    const allowed = new Set([
      "asset_id",
      "integrity_ok",
      "entity_id",
      "authority_id",
      "issuer_id",
      "action",
      "resource",
      "context",
      "process_evidence",
    ]);
    const fields: Record<string, any> = {};
    for (const [key, value] of Object.entries(data)) {
      if (allowed.has(key)) fields[key] = value;
    }
    if (!("issuer_id" in fields)) fields.issuer_id = null;

    const required = ["asset_id", "integrity_ok", "entity_id", "authority_id", "action", "resource"];
    const missing = required.filter((f) => !(f in fields)).sort();
    if (missing.length) {
      throw new Error(`Missing fields: ${missing.join(", ")}`);
    }
    const stringFields = ["asset_id", "entity_id", "authority_id", "action", "resource"];
    const invalid = stringFields.filter((field) => typeof fields[field] !== "string" || !fields[field]);
    if (invalid.length) {
      throw new Error(`Fields must be non-empty strings: ${invalid.join(", ")}`);
    }
    if ("issuer_id" in fields && fields.issuer_id !== null && typeof fields.issuer_id !== "string") {
      throw new Error("issuer_id must be a string or null");
    }
    if (typeof fields.integrity_ok !== "boolean") {
      throw new Error("integrity_ok must be a boolean");
    }
    if ("context" in fields && (typeof fields.context !== "object" || fields.context === null || Array.isArray(fields.context))) {
      throw new Error("context must be a JSON object");
    }
    if (
      "process_evidence" in fields &&
      fields.process_evidence !== null &&
      (typeof fields.process_evidence !== "object" || Array.isArray(fields.process_evidence))
    ) {
      throw new Error("process_evidence must be a JSON object or null");
    }
    // Runtime checks above guarantee the required fields are present and well-typed.
    return fields as any;
  }

  private serializeResponse(response: AuthorizationResponse | RecognitionResponse): Record<string, unknown> {
    const isRecognition = "recognized" in response;
    const result: Record<string, unknown> = {
      [isRecognition ? "recognized" : "authorized"]: isRecognition
        ? (response as RecognitionResponse).recognized
        : (response as AuthorizationResponse).authorized,
    };
    for (const field of ["expires", "policy_epoch", "evidence", "reason", "policy_requirements"] as const) {
      const value = (response as unknown as Record<string, unknown>)[field];
      if (value !== null && value !== undefined) {
        result[field] = value;
      }
    }
    return result;
  }

  private emitAuditEvent(
    eventType: string,
    profile: VerificationProfile,
    useGateway: boolean,
    result: Record<string, unknown>,
  ): void {
    const event = {
      event_type: eventType,
      profile: profile.id ?? String(profile),
      use_gateway: useGateway,
      verification_mode: result.verification_mode,
      trust_outcome: result.trust_outcome,
      policy_freshness: result.policy_freshness,
    };
    console.log("cawg_trqp_http_audit", JSON.stringify(event, Object.keys(event).sort()));
  }

  run(host = "127.0.0.1", port = 5000): void {
    this.app.listen(port, host);
  }
}
