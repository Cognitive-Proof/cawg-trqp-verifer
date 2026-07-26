import { MongoClient, type Document } from "mongodb";

export interface MongoConnectionOptions {
  /** MongoDB connection string. Default: MONGO_URI env var, else mongodb://localhost:27017. */
  uri?: string;
  /** Database name. Default: MONGO_DB_NAME env var, else the client's default database. */
  dbName?: string;
}

// One shared connection per process, cached on globalThis - mirrors the
// pattern used by the other storage plugins in this monorepo, so repeated
// getCollection() calls don't each open their own connection.
const globalForMongo = globalThis as unknown as {
  cawgTrqpMongoClient?: MongoClient;
  cawgTrqpMongoClientPromise?: Promise<MongoClient>;
};

function resolveUri(uri?: string): string {
  return uri ?? process.env.MONGO_URI ?? "mongodb://localhost:27017";
}

async function getConnectedClient(uri?: string): Promise<MongoClient> {
  if (!globalForMongo.cawgTrqpMongoClient) {
    globalForMongo.cawgTrqpMongoClient = new MongoClient(resolveUri(uri));
  }
  if (!globalForMongo.cawgTrqpMongoClientPromise) {
    globalForMongo.cawgTrqpMongoClientPromise = globalForMongo.cawgTrqpMongoClient.connect();
  }
  return globalForMongo.cawgTrqpMongoClientPromise;
}

export async function getCollection<T extends Document>(
  collectionName: string,
  options: MongoConnectionOptions = {},
) {
  const client = await getConnectedClient(options.uri);
  const dbName = options.dbName ?? process.env.MONGO_DB_NAME;
  return client.db(dbName).collection<T>(collectionName);
}
