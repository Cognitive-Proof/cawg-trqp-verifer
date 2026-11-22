import { MongoClient, type Document } from "mongodb";

export interface MongoConnectionOptions {
  /** MongoDB connection string. Default: MONGO_URI env var, else mongodb://localhost:27017. */
  uri?: string;
  /** Database name. Default: MONGO_DB_NAME env var, else the client's default database. */
  dbName?: string;
}

// One shared connection per process, cached on globalThis, as the other
// storage plugins in this monorepo do.
const globalForMongo = globalThis as unknown as {
  cawgTrqpAdminMongoClient?: MongoClient;
  cawgTrqpAdminMongoClientPromise?: Promise<MongoClient>;
};

async function connectedClient(uri?: string): Promise<MongoClient> {
  if (!globalForMongo.cawgTrqpAdminMongoClient) {
    globalForMongo.cawgTrqpAdminMongoClient = new MongoClient(uri ?? process.env.MONGO_URI ?? "mongodb://localhost:27017");
  }
  if (!globalForMongo.cawgTrqpAdminMongoClientPromise) {
    globalForMongo.cawgTrqpAdminMongoClientPromise = globalForMongo.cawgTrqpAdminMongoClient.connect();
  }
  return globalForMongo.cawgTrqpAdminMongoClientPromise;
}

export async function getCollection<T extends Document>(name: string, options: MongoConnectionOptions = {}) {
  const client = await connectedClient(options.uri);
  return client.db(options.dbName ?? process.env.MONGO_DB_NAME).collection<T>(name);
}

