import { beforeEach, describe, expect, it, vi } from "vitest";

const calls: { op: string; collection: string; args: unknown[] }[] = [];
let returned: unknown = null;

function collection(name: string) {
  const record =
    (op: string) =>
    (...args: unknown[]) => {
      calls.push({ op, collection: name, args });
      return op === "find" ? { toArray: async () => (Array.isArray(returned) ? returned : []) } : Promise.resolve(returned);
    };
  return {
    insertOne: record("insertOne"),
    findOne: record("findOne"),
    find: record("find"),
    findOneAndUpdate: record("findOneAndUpdate"),
    findOneAndDelete: record("findOneAndDelete"),
  };
}

vi.mock("../client.js", () => ({
  getCollection: vi.fn(async (name: string) => collection(name)),
}));

const { MongoAdminStore } = await import("../mongo.js");

describe("MongoAdminStore", () => {
  beforeEach(() => {
    calls.length = 0;
    returned = null;
  });

  it("stores grants in the collection MongoPolicyService reads, keyed by id", async () => {
    const store = new MongoAdminStore();
    await store.insertGrant({ id: "g1", entity_id: "did:key:z6Mk1" } as never);
    expect(calls[0]).toMatchObject({ op: "insertOne", collection: "authorizations" });
    expect(calls[0].args[0]).toMatchObject({ _id: "g1", entity_id: "did:key:z6Mk1" });
    expect(calls[0].args[0]).not.toHaveProperty("id");
  });

  it("maps _id back to id", async () => {
    returned = { _id: "r1", status: "pending" };
    expect(await new MongoAdminStore().getRequest("r1")).toEqual({ id: "r1", status: "pending" });
  });

  it("decides only pending requests, atomically", async () => {
    await new MongoAdminStore().decidePending("r1", { id: "ignored", status: "approved" });
    expect(calls[0]).toMatchObject({ op: "findOneAndUpdate", collection: "access_requests" });
    expect(calls[0].args.slice(0, 2)).toEqual([{ _id: "r1", status: "pending" }, { $set: { status: "approved" } }]);
  });

  it("revokes only active grants, atomically", async () => {
    await new MongoAdminStore({ grantsCollection: "registry_grants" }).revokeActive("g1", { authorized: false });
    expect(calls[0]).toMatchObject({ op: "findOneAndUpdate", collection: "registry_grants" });
    expect(calls[0].args[0]).toEqual({ _id: "g1", revoked_at: null });
  });

  it("filters active grants by revoked_at and drops undefined filters", async () => {
    const store = new MongoAdminStore();
    await store.listGrants({ entity_id: "did:key:z6Mk1", action: undefined, active: true });
    await store.listGrants({ active: false });
    expect(calls[0].args[0]).toEqual({ entity_id: "did:key:z6Mk1", revoked_at: null });
    expect(calls[1].args[0]).toEqual({ revoked_at: { $ne: null } });
  });

  it("takes challenges with a single findOneAndDelete", async () => {
    returned = { _id: "c1", expires_at: "2026-11-21T12:05:00Z" };
    expect(await new MongoAdminStore().takeChallenge("c1")).toEqual({ id: "c1", expires_at: "2026-11-21T12:05:00Z" });
    expect(calls[0]).toMatchObject({ op: "findOneAndDelete", collection: "access_challenges" });
  });
});
