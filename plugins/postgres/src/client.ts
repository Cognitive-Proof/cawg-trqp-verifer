import { Pool } from "pg";

export interface PostgresConnectionOptions {
  /** Full Postgres connection string. Default: POSTGRES_URI env var, else postgres://localhost:5432/trqp. */
  uri?: string;
}

// One shared connection pool per process, cached on globalThis - mirrors the
// pattern used by the other storage plugins in this monorepo.
const globalForPostgres = globalThis as unknown as { cawgTrqpPostgresPool?: Pool };

function resolveUri(uri?: string): string {
  return uri ?? process.env.POSTGRES_URI ?? "postgres://localhost:5432/trqp";
}

export function getPostgresPool(uri?: string): Pool {
  if (!globalForPostgres.cawgTrqpPostgresPool) {
    globalForPostgres.cawgTrqpPostgresPool = new Pool({ connectionString: resolveUri(uri) });
  }
  return globalForPostgres.cawgTrqpPostgresPool;
}
