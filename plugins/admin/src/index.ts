// Trust registry administration for cawg-trqp-refimpl. RegistryAdmin runs
// the request / approve / reject / revoke workflow over an AdminStore;
// AdminPolicyService answers TRQP queries from the resulting grants (and is
// a drop-in PolicyService for HTTPTRQPService); createAdminRouter exposes the
// workflow over HTTP and is imported separately, from
// "@cognitiveproof/cawg-trqp-plugin-admin/router", so express stays optional.

export * from "./types.js";
export * from "./store.js";
export * from "./proof.js";
export * from "./admin.js";
export * from "./policy.js";
export { MongoAdminStore, type MongoAdminStoreOptions } from "./mongo.js";
