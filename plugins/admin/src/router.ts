import { timingSafeEqual } from "node:crypto";
import express, { type NextFunction, type Request, type Response, type Router } from "express";
import { AdminError, type RegistryAdmin } from "./admin.js";
import type { RequestStatus } from "./types.js";

export interface AdminRouterOptions {
  /**
   * Identifies the administrator making an /admin request, or returns null
   * to refuse it. The returned name is recorded on every decision and in
   * the audit log. See bearerTokenAdmins() for a simple implementation.
   */
  authenticateAdmin: (req: Request) => Promise<string | null> | string | null;
}

/** authenticateAdmin for a fixed set of bearer tokens: `{ token: adminName }`. */
export function bearerTokenAdmins(tokens: Record<string, string>): (req: Request) => string | null {
  const entries = Object.entries(tokens).map(([token, name]) => [Buffer.from(token), name] as const);
  return (req) => {
    const header = req.headers.authorization ?? "";
    if (!header.startsWith("Bearer ")) return null;
    const presented = Buffer.from(header.slice("Bearer ".length));
    const match = entries.find(([token]) => token.length === presented.length && timingSafeEqual(token, presented));
    return match ? match[1] : null;
  };
}

function problem(res: Response, status: number, title: string, detail: string): void {
  res.status(status).contentType("application/problem+json").json({ type: "about:blank", title, status, detail });
}

type Handler = (req: Request, res: Response) => Promise<void>;

/** Express 4 doesn't await handlers; route rejections to the error handler. */
const wrap = (fn: Handler) => (req: Request, res: Response, next: NextFunction) => {
  fn(req, res).catch(next);
};

function requireStrings(body: Record<string, unknown>, fields: string[]): string | null {
  const bad = fields.filter((f) => typeof body[f] !== "string" || body[f] === "");
  return bad.length ? `Fields must be non-empty strings: ${bad.join(", ")}` : null;
}

const STATUSES: RequestStatus[] = ["pending", "approved", "rejected"];

/**
 * HTTP API for RegistryAdmin. Mount it next to the TRQP endpoints, e.g.
 * `new HTTPTRQPService(new AdminPolicyService({ store })).app.use("/registry", createAdminRouter(admin, …))`.
 *
 * Public:  GET /permissions, POST /challenges, POST /requests, GET /requests/:id
 * Admin:   GET /admin/requests, POST /admin/requests/:id/approve|reject,
 *          GET /admin/grants, POST /admin/grants, POST /admin/grants/:id/revoke,
 *          GET /admin/audit
 */
export function createAdminRouter(admin: RegistryAdmin, options: AdminRouterOptions): Router {
  const router = express.Router();
  router.use(express.json({ limit: "64kb" }));

  router.get("/permissions", (_req, res) => {
    res.json({ requestable: admin.requestable });
  });

  router.post(
    "/challenges",
    wrap(async (_req, res) => {
      const challenge = await admin.createChallenge();
      res.status(201).json({
        challenge: challenge.id,
        expires_at: challenge.expires_at,
        sign: 'UTF-8 bytes of "trqp-access-request:" + JSON.stringify([challenge, entity_id, authority_id, action, resource])',
      });
    }),
  );

  router.post(
    "/requests",
    wrap(async (req, res) => {
      const body = (req.body ?? {}) as Record<string, unknown>;
      const invalid = requireStrings(body, ["entity_id", "authority_id", "action", "resource", "challenge", "signature"]);
      if (invalid) return problem(res, 400, "Bad Request", invalid);
      const request = await admin.requestAccess(body as never);
      res.status(201).json(request);
    }),
  );

  router.get(
    "/requests/:id",
    wrap(async (req, res) => {
      const request = await admin.getRequest(req.params.id);
      if (!request) return problem(res, 404, "Not found", `No request ${req.params.id}`);
      res.json(request);
    }),
  );

  // Everything under /admin needs an administrator.
  router.use("/admin", (req, res, next) => {
    Promise.resolve(options.authenticateAdmin(req))
      .then((name) => {
        if (!name) return problem(res, 401, "Unauthorized", "Administrator credentials required");
        res.locals.admin = name;
        next();
      })
      .catch(next);
  });

  router.get(
    "/admin/requests",
    wrap(async (req, res) => {
      const status = req.query.status as string | undefined;
      if (status !== undefined && !STATUSES.includes(status as RequestStatus)) {
        return problem(res, 400, "Bad Request", `status must be one of ${STATUSES.join(", ")}`);
      }
      res.json(
        await admin.listRequests({
          status: status as RequestStatus | undefined,
          entity_id: req.query.entity_id as string | undefined,
          authority_id: req.query.authority_id as string | undefined,
        }),
      );
    }),
  );

  for (const decision of ["approve", "reject"] as const) {
    router.post(
      `/admin/requests/:id/${decision}`,
      wrap(async (req, res) => {
        const note = typeof req.body?.note === "string" ? req.body.note : null;
        const result =
          decision === "approve"
            ? await admin.approve(req.params.id, res.locals.admin, note)
            : { request: await admin.reject(req.params.id, res.locals.admin, note) };
        res.json(result);
      }),
    );
  }

  router.get(
    "/admin/grants",
    wrap(async (req, res) => {
      const active = req.query.active === undefined ? undefined : req.query.active === "true";
      res.json(
        await admin.listGrants({
          entity_id: req.query.entity_id as string | undefined,
          authority_id: req.query.authority_id as string | undefined,
          action: req.query.action as string | undefined,
          resource: req.query.resource as string | undefined,
          active,
        }),
      );
    }),
  );

  router.post(
    "/admin/grants",
    wrap(async (req, res) => {
      const body = (req.body ?? {}) as Record<string, unknown>;
      const invalid = requireStrings(body, ["entity_id", "authority_id", "action", "resource"]);
      if (invalid) return problem(res, 400, "Bad Request", invalid);
      const evidence = Array.isArray(body.evidence) ? body.evidence.filter((e): e is string => typeof e === "string") : [];
      const grant = await admin.grantDirectly(
        body.entity_id as string,
        { authority_id: body.authority_id as string, action: body.action as string, resource: body.resource as string },
        res.locals.admin,
        evidence,
      );
      res.status(201).json(grant);
    }),
  );

  router.post(
    "/admin/grants/:id/revoke",
    wrap(async (req, res) => {
      const reason = typeof req.body?.reason === "string" ? req.body.reason : null;
      res.json(await admin.revoke(req.params.id, res.locals.admin, reason));
    }),
  );

  router.get(
    "/admin/audit",
    wrap(async (req, res) => {
      res.json(await admin.auditLog(req.query.subject_id as string | undefined));
    }),
  );

  router.use((err: unknown, _req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) return next(err);
    if (err instanceof AdminError) return problem(res, err.status, err.title, err.message);
    if (err instanceof SyntaxError) return problem(res, 400, "Bad Request", "Request body must be valid JSON");
    console.error("cawg_trqp_admin_error", err);
    problem(res, 500, "Internal Server Error", "The registry could not complete the request");
  });

  return router;
}
