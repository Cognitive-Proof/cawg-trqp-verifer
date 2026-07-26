import mysql, { type Pool } from "mysql2/promise";

export interface MySQLConnectionOptions {
  /** Full MySQL connection string. Default: MYSQL_URI env var, else mysql://root@localhost:3306/trqp. */
  uri?: string;
}

// One shared connection pool per process, cached on globalThis - mirrors the
// pattern used by the other storage plugins in this monorepo.
const globalForMySQL = globalThis as unknown as { cawgTrqpMySQLPool?: Pool };

function resolveUri(uri?: string): string {
  return uri ?? process.env.MYSQL_URI ?? "mysql://root@localhost:3306/trqp";
}

export function getMySQLPool(uri?: string): Pool {
  if (!globalForMySQL.cawgTrqpMySQLPool) {
    globalForMySQL.cawgTrqpMySQLPool = mysql.createPool(resolveUri(uri));
  }
  return globalForMySQL.cawgTrqpMySQLPool;
}
