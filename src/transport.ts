export class TransportConstraintError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TransportConstraintError";
  }
}

export interface FeedTransportMetadata {
  mode: string;
  integrity: string;
  available: boolean;
  channel: string;
}

export function createFeedTransportMetadata(
  fields: Partial<FeedTransportMetadata> & Pick<FeedTransportMetadata, "mode" | "integrity">,
): FeedTransportMetadata {
  return {
    available: true,
    channel: "full",
    ...fields,
  };
}

export function feedTransportMetadataToDict(metadata: FeedTransportMetadata): Record<string, unknown> {
  return {
    mode: metadata.mode,
    integrity: metadata.integrity,
    available: metadata.available,
    channel: metadata.channel,
  };
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
