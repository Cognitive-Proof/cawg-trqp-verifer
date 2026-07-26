// FeedTransportMetadata is defined in @cognitiveproof/cawg-trqp-plugin-types (the shared
// contract package plugin authors depend on) - re-exported here so existing
// internal imports (`from "./transport.js"`) keep working unchanged.
export type { FeedTransportMetadata } from "@cognitiveproof/cawg-trqp-plugin-types";
export { createFeedTransportMetadata, feedTransportMetadataToDict } from "@cognitiveproof/cawg-trqp-plugin-types";
import type { FeedTransportMetadata } from "@cognitiveproof/cawg-trqp-plugin-types";

export class TransportConstraintError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TransportConstraintError";
  }
}

export function evaluateTransportConstraints(
  required: Record<string, unknown>,
  actual: FeedTransportMetadata,
): string[] {
  const failures: string[] = [];
  const requiredMode = required.mode as string | undefined;
  // gateway is treated as a stricter mediation path than direct http.
  // Profiles requiring direct http may accept gateway transport because the
  // gateway preserves or strengthens the trust boundary. Profiles requiring
  // gateway transport reject plain http because the mediation guarantee is absent.
  const compatibleModes: Record<string, Set<string>> = {
    local: new Set(["local"]),
    http: new Set(["http", "gateway"]),
    gateway: new Set(["gateway"]),
  };
  if (requiredMode && !(compatibleModes[requiredMode] ?? new Set([requiredMode])).has(actual.mode)) {
    failures.push(`transport mode '${actual.mode}' does not satisfy required mode '${requiredMode}'`);
  }

  const integrityRank: Record<string, number> = { none: 0, tls: 1, signed: 2 };
  const requiredIntegrity = (required.integrity as string | undefined) ?? "none";
  const actualRank = integrityRank[actual.integrity] ?? -1;
  const requiredRank = integrityRank[requiredIntegrity] ?? 0;
  if (actualRank < requiredRank) {
    failures.push(`transport integrity '${actual.integrity}' is below required level '${requiredIntegrity}'`);
  }

  const availabilityRequirement = (required.availability_requirement as string | undefined) ?? "best_effort";
  if (availabilityRequirement === "required" && !actual.available) {
    failures.push("required transport feed is unavailable");
  }

  return failures;
}
