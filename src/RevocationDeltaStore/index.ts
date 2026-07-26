// RevocationDeltaStore/RevocationCheckResult are defined in
// @cognitiveproof/cawg-trqp-plugin-types (the shared contract package plugin authors depend
// on) - re-exported here so existing internal imports
// (`from "./RevocationDeltaStore/index.js"`) keep working unchanged.
export type { RevocationCheckResult, RevocationDeltaStore } from "@cognitiveproof/cawg-trqp-plugin-types";
import type { RevocationCheckResult, RevocationDeltaStore } from "@cognitiveproof/cawg-trqp-plugin-types";

interface DeltaState {
  revokedEntities: Set<string>;
  policyEpoch: string | null;
}

/** In-process reference adapter - see the interface doc above for its limitation. */
export class InMemoryRevocationDeltaStore implements RevocationDeltaStore {
  private state: DeltaState | null = null;

  async set(revokedEntities: string[], policyEpoch: string | null = null): Promise<void> {
    this.state = { revokedEntities: new Set(revokedEntities), policyEpoch };
  }

  async check(entityId: string): Promise<RevocationCheckResult> {
    if (this.state !== null && this.state.revokedEntities.has(entityId)) {
      return {
        revoked: true,
        reason: `revoked_in_epoch_${this.state.policyEpoch ?? "unknown"}`,
        policyEpoch: this.state.policyEpoch,
      };
    }
    return { revoked: false, reason: null, policyEpoch: null };
  }
}
