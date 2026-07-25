export class PermissionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PermissionError";
  }
}

export function requireScope(grantedScopes: Set<string>, requiredScope: string): void {
  if (!grantedScopes.has(requiredScope)) {
    throw new PermissionError(`missing required scope: ${requiredScope}`);
  }
}
