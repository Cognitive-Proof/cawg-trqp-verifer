export interface RevocationCheckResult {
  revoked: boolean;
  reason: string | null;
  policyEpoch: string | null;
}

/**
 * Contract for tracking an urgent, out-of-band revocation delta pushed into a
 * running verifier between normal policy refresh cycles (see
 * Verifier.applyRevocationDelta). Async so a shared backend (Redis, a
 * pub/sub-fed store, etc.) is a real drop-in - InMemoryRevocationDeltaStore
 * below only affects the single process it's constructed in, which is fine
 * for one instance but silently has no effect on any other instance in a
 * horizontally-scaled deployment: applying a delta on instance A leaves
 * instance B still enforcing the old, un-revoked state until its own
 * process-local copy is separately updated.
 */
export interface RevocationDeltaStore {
  set(revokedEntities: string[], policyEpoch?: string | null): Promise<void>;
  check(entityId: string): Promise<RevocationCheckResult>;
}

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
