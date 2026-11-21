import { getCollection, type MongoConnectionOptions } from "./client.js";
import type { AdminStore, GrantFilter, RequestFilter } from "./store.js";
import type { AccessRequest, AuditEvent, Challenge, Grant } from "./types.js";

export interface MongoAdminStoreOptions extends MongoConnectionOptions {
  /**
   * Collection for grants. Defaults to "authorizations", the collection the
   * MongoDB plugin's MongoPolicyService reads, so its (non time-aware)
   * answers stay consistent with the grants this plugin writes.
   */
  grantsCollection?: string;
  requestsCollection?: string;
  challengesCollection?: string;
  auditCollection?: string;
}

// Documents are stored with the record's id as _id. Queries use only
// equality filters and single-document conditional updates, which keeps the
// store compatible with MongoDB-compatible backends such as Firestore.
type WithMongoId<T extends { id: string }> = Omit<T, "id"> & { _id: string };

function toDoc<T extends { id: string }>(record: T): WithMongoId<T> {
  const { id, ...rest } = record;
  return { _id: id, ...rest } as WithMongoId<T>;
}

function fromDoc<T extends { id: string }>(doc: WithMongoId<T> | null): T | null {
  if (!doc) return null;
  const { _id, ...rest } = doc;
  return { id: _id, ...rest } as unknown as T;
}

function definedOnly(filter: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(filter).filter(([, v]) => v !== undefined));
}

/** MongoDB-backed AdminStore. */
export class MongoAdminStore implements AdminStore {
  private readonly options: MongoAdminStoreOptions;
  private readonly names: Required<Pick<MongoAdminStoreOptions, "grantsCollection" | "requestsCollection" | "challengesCollection" | "auditCollection">>;

  constructor(options: MongoAdminStoreOptions = {}) {
    this.options = { uri: options.uri, dbName: options.dbName };
    this.names = {
      grantsCollection: options.grantsCollection ?? "authorizations",
      requestsCollection: options.requestsCollection ?? "access_requests",
      challengesCollection: options.challengesCollection ?? "access_challenges",
      auditCollection: options.auditCollection ?? "admin_audit",
    };
  }

  private requests() {
    return getCollection<WithMongoId<AccessRequest>>(this.names.requestsCollection, this.options);
  }

  private grants() {
    return getCollection<WithMongoId<Grant>>(this.names.grantsCollection, this.options);
  }

  async insertRequest(request: AccessRequest): Promise<void> {
    await (await this.requests()).insertOne(toDoc(request));
  }

  async getRequest(id: string): Promise<AccessRequest | null> {
    return fromDoc<AccessRequest>(await (await this.requests()).findOne({ _id: id }));
  }

  async listRequests(filter: RequestFilter = {}): Promise<AccessRequest[]> {
    const docs = await (await this.requests()).find(definedOnly({ ...filter })).toArray();
    return docs.map((d) => fromDoc<AccessRequest>(d)!);
  }

  async decidePending(id: string, patch: Partial<AccessRequest>): Promise<AccessRequest | null> {
    const { id: _ignored, ...fields } = patch;
    const doc = await (await this.requests()).findOneAndUpdate(
      { _id: id, status: "pending" },
      { $set: fields },
      { returnDocument: "after" },
    );
    return fromDoc<AccessRequest>(doc);
  }

  async insertGrant(grant: Grant): Promise<void> {
    await (await this.grants()).insertOne(toDoc(grant));
  }

  async getGrant(id: string): Promise<Grant | null> {
    return fromDoc<Grant>(await (await this.grants()).findOne({ _id: id }));
  }

  async listGrants(filter: GrantFilter = {}): Promise<Grant[]> {
    const { active, ...fields } = filter;
    const query: Record<string, unknown> = definedOnly(fields);
    if (active !== undefined) query.revoked_at = active ? null : { $ne: null };
    const docs = await (await this.grants()).find(query).toArray();
    return docs.map((d) => fromDoc<Grant>(d)!);
  }

  async revokeActive(id: string, patch: Partial<Grant>): Promise<Grant | null> {
    const { id: _ignored, ...fields } = patch;
    const doc = await (await this.grants()).findOneAndUpdate(
      { _id: id, revoked_at: null },
      { $set: fields },
      { returnDocument: "after" },
    );
    return fromDoc<Grant>(doc);
  }

  async insertChallenge(challenge: Challenge): Promise<void> {
    await (await getCollection<WithMongoId<Challenge>>(this.names.challengesCollection, this.options)).insertOne(toDoc(challenge));
  }

  async takeChallenge(id: string): Promise<Challenge | null> {
    const col = await getCollection<WithMongoId<Challenge>>(this.names.challengesCollection, this.options);
    return fromDoc<Challenge>(await col.findOneAndDelete({ _id: id }));
  }

  async appendAudit(event: AuditEvent): Promise<void> {
    await (await getCollection<AuditEvent>(this.names.auditCollection, this.options)).insertOne({ ...event });
  }

  async listAudit(subjectId?: string): Promise<AuditEvent[]> {
    const col = await getCollection<AuditEvent>(this.names.auditCollection, this.options);
    const docs = await col.find(subjectId === undefined ? {} : { subject_id: subjectId }).toArray();
    return docs.map(({ _id, ...event }) => event as AuditEvent);
  }
}
