import { randomUUID } from "node:crypto";
import { accessRequestMessage, decodeSignature, DidKeyProofVerifier, type ProofVerifier } from "./proof.js";
import type { AdminStore, GrantFilter, RequestFilter } from "./store.js";
import type { AccessRequest, Applicant, AuditAction, AuditEvent, Challenge, Grant, Permission } from "./types.js";

/** A refused admin operation. `status` is the HTTP status the router answers with. */
export class AdminError extends Error {
  constructor(
    readonly status: number,
    readonly title: string,
    detail: string,
  ) {
    super(detail);
    this.name = "AdminError";
  }
}

export interface AccessRequestInput extends Permission {
  entity_id: string;
  context?: Record<string, unknown>;
  applicant?: Applicant;
  /** A challenge id from createChallenge(). Single use. */
  challenge: string;
  /** Signature (base64 or base64url) over accessRequestMessage(challenge, entity_id, permission). */
  signature: string;
}

export interface RegistryAdminOptions {
  store: AdminStore;
  /** The permissions applicants may ask for. Requests for anything else are refused. */
  requestable: Permission[];
  /** Proof-of-possession verifiers, tried in order. Default: did:key Ed25519. */
  proofVerifiers?: ProofVerifier[];
  /**
   * Deployment-specific checks on an applicant, run after proof of possession
   * (e.g. "holds a certificate from our CA for this email"). Throw an
   * AdminError to refuse; return evidence strings to record on the request.
   */
  checkApplicant?: (input: AccessRequestInput) => Promise<string[] | void>;
  /** Seconds a challenge stays valid. Default 300. */
  challengeTtlSeconds?: number;
  /** If set, grants expire this many seconds after approval. Default: no expiry. */
  grantTtlSeconds?: number | null;
  /** Recorded on every grant as policy_epoch. */
  policyEpoch?: string | null;
  now?: () => Date;
  newId?: () => string;
}

const iso = (d: Date) => d.toISOString();

function samePermission(a: Permission, b: Permission): boolean {
  return a.authority_id === b.authority_id && a.action === b.action && a.resource === b.resource;
}

/**
 * The registry administration workflow: applicants request a permission and
 * prove control of their identifier's key; administrators approve, reject
 * and revoke. Approved requests become grants that AdminPolicyService answers
 * TRQP queries from.
 */
export class RegistryAdmin {
  readonly store: AdminStore;
  private readonly options: Required<Omit<RegistryAdminOptions, "checkApplicant" | "store">> &
    Pick<RegistryAdminOptions, "checkApplicant">;

  constructor(options: RegistryAdminOptions) {
    this.store = options.store;
    this.options = {
      requestable: options.requestable,
      proofVerifiers: options.proofVerifiers ?? [new DidKeyProofVerifier()],
      checkApplicant: options.checkApplicant,
      challengeTtlSeconds: options.challengeTtlSeconds ?? 300,
      grantTtlSeconds: options.grantTtlSeconds ?? null,
      policyEpoch: options.policyEpoch ?? null,
      now: options.now ?? (() => new Date()),
      newId: options.newId ?? randomUUID,
    };
  }

  /** The permissions applicants may request. */
  get requestable(): Permission[] {
    return this.options.requestable.map((p) => ({ ...p }));
  }

  async createChallenge(): Promise<Challenge> {
    const expires = new Date(this.options.now().getTime() + this.options.challengeTtlSeconds * 1000);
    const challenge = { id: this.options.newId(), expires_at: iso(expires) };
    await this.store.insertChallenge(challenge);
    return challenge;
  }

  /**
   * Accepts a request after checking it is for a requestable permission, the
   * challenge is fresh, and the signature proves control of entity_id's key.
   * A second request for the same permission while one is pending returns
   * the pending one.
   */
  async requestAccess(input: AccessRequestInput): Promise<AccessRequest> {
    const permission: Permission = { authority_id: input.authority_id, action: input.action, resource: input.resource };
    if (!this.options.requestable.some((p) => samePermission(p, permission))) {
      throw new AdminError(404, "Not requestable", `${input.action} on ${input.resource} under ${input.authority_id} cannot be requested here`);
    }

    const challenge = await this.store.takeChallenge(input.challenge);
    if (!challenge || challenge.expires_at <= iso(this.options.now())) {
      throw new AdminError(400, "Invalid challenge", "The challenge is unknown, already used, or expired");
    }

    const verifier = this.options.proofVerifiers.find((v) => v.supports(input.entity_id));
    if (!verifier) {
      throw new AdminError(400, "Unsupported identifier", `No proof verifier supports ${input.entity_id}`);
    }
    const message = accessRequestMessage(input.challenge, input.entity_id, permission);
    if (!(await verifier.verify(input.entity_id, message, decodeSignature(input.signature)))) {
      throw new AdminError(403, "Proof of possession failed", `The signature was not made with ${input.entity_id}'s key`);
    }

    if ((await this.store.listGrants({ entity_id: input.entity_id, ...permission, active: true })).length > 0) {
      throw new AdminError(409, "Already authorized", `${input.entity_id} already holds this permission`);
    }
    const pending = await this.store.listRequests({ entity_id: input.entity_id, authority_id: permission.authority_id, status: "pending" });
    const existing = pending.find((r) => samePermission(r, permission));
    if (existing) return existing;

    const extraEvidence = (await this.options.checkApplicant?.(input)) ?? [];
    const request: AccessRequest = {
      id: this.options.newId(),
      entity_id: input.entity_id,
      ...permission,
      context: input.context ?? {},
      applicant: input.applicant ?? {},
      evidence: [`proof-of-possession:${input.challenge}`, ...extraEvidence],
      status: "pending",
      created_at: iso(this.options.now()),
      decided_at: null,
      decided_by: null,
      decision_note: null,
      grant_id: null,
    };
    await this.store.insertRequest(request);
    await this.audit("request.created", input.entity_id, request.id, input.entity_id, { ...permission });
    return request;
  }

  /** Approves a pending request and creates its grant. */
  async approve(requestId: string, admin: string, note: string | null = null): Promise<{ request: AccessRequest; grant: Grant }> {
    const grantId = this.options.newId();
    const now = this.options.now();
    const request = await this.store.decidePending(requestId, {
      status: "approved",
      decided_at: iso(now),
      decided_by: admin,
      decision_note: note,
      grant_id: grantId,
    });
    if (!request) throw await this.notPending(requestId);

    const grant = this.newGrant(grantId, request.entity_id, request, admin, now, {
      context: request.context,
      evidence: [`request:${request.id}`, `approved-by:${admin}`, ...request.evidence],
      request_id: request.id,
    });
    await this.store.insertGrant(grant);
    await this.audit("request.approved", admin, request.id, request.entity_id, { note });
    await this.audit("grant.created", admin, grant.id, grant.entity_id, { request_id: request.id });
    return { request, grant };
  }

  async reject(requestId: string, admin: string, note: string | null = null): Promise<AccessRequest> {
    const request = await this.store.decidePending(requestId, {
      status: "rejected",
      decided_at: iso(this.options.now()),
      decided_by: admin,
      decision_note: note,
    });
    if (!request) throw await this.notPending(requestId);
    await this.audit("request.rejected", admin, request.id, request.entity_id, { note });
    return request;
  }

  /**
   * Grants a permission without a request: for standing grants an operator
   * configures, such as a service key's right to publish status lists.
   * Returns the existing active grant if there is one.
   */
  async grantDirectly(entityId: string, permission: Permission, admin: string, evidence: string[] = []): Promise<Grant> {
    const [active] = await this.store.listGrants({ entity_id: entityId, ...permission, active: true });
    if (active) return active;
    const grant = this.newGrant(this.options.newId(), entityId, permission, admin, this.options.now(), {
      evidence: [`granted-by:${admin}`, ...evidence],
    });
    await this.store.insertGrant(grant);
    await this.audit("grant.created", admin, grant.id, entityId, { ...permission });
    return grant;
  }

  /**
   * Revokes a grant from now on. The grant keeps its history, so
   * AdminPolicyService still answers "authorized" for times before the
   * revocation.
   */
  async revoke(grantId: string, admin: string, reason: string | null = null): Promise<Grant> {
    const existing = await this.store.getGrant(grantId);
    if (!existing) throw new AdminError(404, "Not found", `No grant ${grantId}`);
    const grant = await this.store.revokeActive(grantId, {
      authorized: false,
      reason: "revoked",
      revoked_at: iso(this.options.now()),
      revoked_by: admin,
      evidence: [...existing.evidence, `revoked-by:${admin}`, ...(reason ? [`revocation-reason:${reason}`] : [])],
    });
    if (!grant) throw new AdminError(409, "Already revoked", `Grant ${grantId} was already revoked`);
    await this.audit("grant.revoked", admin, grant.id, grant.entity_id, { reason });
    return grant;
  }

  getRequest(id: string): Promise<AccessRequest | null> {
    return this.store.getRequest(id);
  }

  listRequests(filter?: RequestFilter): Promise<AccessRequest[]> {
    return this.store.listRequests(filter);
  }

  listGrants(filter?: GrantFilter): Promise<Grant[]> {
    return this.store.listGrants(filter);
  }

  auditLog(subjectId?: string): Promise<AuditEvent[]> {
    return this.store.listAudit(subjectId);
  }

  private newGrant(
    id: string,
    entityId: string,
    permission: Permission,
    admin: string,
    now: Date,
    extra: Pick<Grant, "evidence"> & Partial<Pick<Grant, "context" | "request_id">>,
  ): Grant {
    const ttl = this.options.grantTtlSeconds;
    return {
      id,
      entity_id: entityId,
      authority_id: permission.authority_id,
      action: permission.action,
      resource: permission.resource,
      context: extra.context ?? {},
      authorized: true,
      expires: ttl === null ? null : iso(new Date(now.getTime() + ttl * 1000)),
      policy_epoch: this.options.policyEpoch,
      evidence: extra.evidence,
      reason: null,
      granted_at: iso(now),
      granted_by: admin,
      revoked_at: null,
      revoked_by: null,
      request_id: extra.request_id ?? null,
    };
  }

  private async notPending(requestId: string): Promise<AdminError> {
    const request = await this.store.getRequest(requestId);
    return request
      ? new AdminError(409, "Already decided", `Request ${requestId} is ${request.status}`)
      : new AdminError(404, "Not found", `No request ${requestId}`);
  }

  private async audit(action: AuditAction, actor: string, subjectId: string, entityId: string, detail: Record<string, unknown>) {
    await this.store.appendAudit({ at: iso(this.options.now()), actor, action, subject_id: subjectId, entity_id: entityId, detail });
  }
}
