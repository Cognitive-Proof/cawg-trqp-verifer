import type { AccessRequest, AuditEvent, Challenge, Grant, RequestStatus } from "./types.js";

export interface RequestFilter {
  status?: RequestStatus;
  entity_id?: string;
  authority_id?: string;
}

export interface GrantFilter {
  entity_id?: string;
  authority_id?: string;
  action?: string;
  resource?: string;
  /** true: only grants that have not been revoked. */
  active?: boolean;
}

/**
 * Storage for the admin workflow. Async throughout, like the other plugin
 * contracts, so a database-backed implementation can do real I/O.
 */
export interface AdminStore {
  insertRequest(request: AccessRequest): Promise<void>;
  getRequest(id: string): Promise<AccessRequest | null>;
  listRequests(filter?: RequestFilter): Promise<AccessRequest[]>;
  /**
   * Applies `patch` only if the request is still `pending`; returns the
   * updated request, or null if it was not pending (already decided).
   */
  decidePending(id: string, patch: Partial<AccessRequest>): Promise<AccessRequest | null>;

  insertGrant(grant: Grant): Promise<void>;
  getGrant(id: string): Promise<Grant | null>;
  listGrants(filter?: GrantFilter): Promise<Grant[]>;
  /** Applies `patch` only if the grant is not yet revoked; returns it, or null. */
  revokeActive(id: string, patch: Partial<Grant>): Promise<Grant | null>;

  insertChallenge(challenge: Challenge): Promise<void>;
  /** Removes and returns the challenge (single use), or null if unknown. */
  takeChallenge(id: string): Promise<Challenge | null>;

  appendAudit(event: AuditEvent): Promise<void>;
  listAudit(subjectId?: string): Promise<AuditEvent[]>;
}

function matches<T extends object>(item: T, filter: Partial<Record<keyof T, unknown>>): boolean {
  return Object.entries(filter).every(([key, value]) => value === undefined || item[key as keyof T] === value);
}

/** In-process store for tests, demos and single-instance deployments. */
export class InMemoryAdminStore implements AdminStore {
  private readonly requests = new Map<string, AccessRequest>();
  private readonly grants = new Map<string, Grant>();
  private readonly challenges = new Map<string, Challenge>();
  private readonly audit: AuditEvent[] = [];

  async insertRequest(request: AccessRequest): Promise<void> {
    this.requests.set(request.id, { ...request });
  }

  async getRequest(id: string): Promise<AccessRequest | null> {
    const request = this.requests.get(id);
    return request ? { ...request } : null;
  }

  async listRequests(filter: RequestFilter = {}): Promise<AccessRequest[]> {
    return [...this.requests.values()].filter((r) => matches(r, filter)).map((r) => ({ ...r }));
  }

  async decidePending(id: string, patch: Partial<AccessRequest>): Promise<AccessRequest | null> {
    const request = this.requests.get(id);
    if (!request || request.status !== "pending") return null;
    const updated = { ...request, ...patch };
    this.requests.set(id, updated);
    return { ...updated };
  }

  async insertGrant(grant: Grant): Promise<void> {
    this.grants.set(grant.id, { ...grant });
  }

  async getGrant(id: string): Promise<Grant | null> {
    const grant = this.grants.get(id);
    return grant ? { ...grant } : null;
  }

  async listGrants(filter: GrantFilter = {}): Promise<Grant[]> {
    const { active, ...fields } = filter;
    return [...this.grants.values()]
      .filter((g) => matches(g, fields) && (active === undefined || (g.revoked_at === null) === active))
      .map((g) => ({ ...g }));
  }

  async revokeActive(id: string, patch: Partial<Grant>): Promise<Grant | null> {
    const grant = this.grants.get(id);
    if (!grant || grant.revoked_at !== null) return null;
    const updated = { ...grant, ...patch };
    this.grants.set(id, updated);
    return { ...updated };
  }

  async insertChallenge(challenge: Challenge): Promise<void> {
    this.challenges.set(challenge.id, { ...challenge });
  }

  async takeChallenge(id: string): Promise<Challenge | null> {
    const challenge = this.challenges.get(id) ?? null;
    this.challenges.delete(id);
    return challenge;
  }

  async appendAudit(event: AuditEvent): Promise<void> {
    this.audit.push({ ...event });
  }

  async listAudit(subjectId?: string): Promise<AuditEvent[]> {
    return this.audit.filter((e) => subjectId === undefined || e.subject_id === subjectId).map((e) => ({ ...e }));
  }
}
