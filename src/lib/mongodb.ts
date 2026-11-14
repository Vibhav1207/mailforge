import dns from "node:dns";
import { Binary, MongoClient, ObjectId, type Db } from "mongodb";
import { appUrl, configured } from "@/lib/server/config";
import { ApiError } from "@/lib/server/errors";

// Set reliable public DNS servers for SRV resolution if local DNS refuses SRV queries
try {
  dns.setServers(["8.8.8.8", "1.1.1.1"]);
} catch {
  // Ignore in restricted environments
}

interface MongoCache { uri: string; promise: Promise<MongoClient> }
declare global { var postvaneMongo: MongoCache | undefined; var mailforgeMongo: MongoCache | undefined; }

export function isMongoConfigured(): boolean {
  return configured(process.env.MONGODB_URI || process.env.MONGO_URL);
}

/**
 * Fallback SRV resolver for environments where the local router/DNS refuses SRV records (ECONNREFUSED).
 * Uses public DNS resolvers (8.8.8.8 and 1.1.1.1) to resolve cluster hostnames and replicaSet attributes.
 */
async function resolveMongoUri(uri: string): Promise<string> {
  if (!uri.startsWith("mongodb+srv://")) return uri;
  try {
    const resolver = new dns.promises.Resolver();
    resolver.setServers(["8.8.8.8", "1.1.1.1"]);
    const parsed = new URL(uri.replace("mongodb+srv://", "http://"));
    const hostname = parsed.hostname;
    const srvRecords = await resolver.resolveSrv(`_mongodb._tcp.${hostname}`);
    if (srvRecords && srvRecords.length > 0) {
      let txtRecords: string[][] = [];
      try {
        txtRecords = await resolver.resolveTxt(hostname);
      } catch {
        // TXT records are optional
      }
      const txtParams = txtRecords.flat().join("&");
      const hosts = srvRecords.map((r) => `${r.name}:${r.port}`).join(",");
      const auth = parsed.username
        ? `${encodeURIComponent(decodeURIComponent(parsed.username))}:${encodeURIComponent(decodeURIComponent(parsed.password))}@`
        : "";
      const pathname = parsed.pathname || "";
      const existingParams = parsed.search ? parsed.search.slice(1) : "";
      const allParams = [txtParams, existingParams, "ssl=true"].filter(Boolean).join("&");
      return `mongodb://${auth}${hosts}${pathname}?${allParams}`;
    }
  } catch (err) {
    console.warn("MongoDB SRV custom DNS resolution fallback error:", (err as Error)?.message || err);
  }
  return uri;
}

let indexesEnsured = false;
async function ensureMongoIndexes(db: Db): Promise<void> {
  if (indexesEnsured) return;
  indexesEnsured = true;
  try {
    await Promise.allSettled([
      db.collection("campaigns").createIndex({ userId: 1, createdAt: -1 }),
      db.collection("campaigns").createIndex({ userId: 1, status: 1 }),
      db.collection("contacts").createIndex({ userId: 1, createdAt: -1 }),
      db.collection("contacts").createIndex({ userId: 1, email: 1 }),
      db.collection("email_templates").createIndex({ userId: 1, createdAt: -1 }),
      db.collection("email_templates").createIndex({ userId: 1, folder: 1 }),
      db.collection("campaignJobs").createIndex({ state: 1, nextRunAt: 1 }),
      db.collection("campaignRecipients").createIndex({ campaignId: 1, userId: 1 }),
      db.collection("campaignRecipients").createIndex({ campaignId: 1, status: 1, nextAttemptAt: 1 }),
      db.collection("emailEvents").createIndex({ campaignId: 1, recipientId: 1 }),
      db.collection("emailEvents").createIndex({ userId: 1, timestamp: -1 }),
      db.collection("template_images").createIndex({ userId: 1, folder: 1 }),
      db.collection("domains").createIndex({ domain: 1, status: 1 }),
      db.collection("users").createIndex({ uid: 1 }),
    ]);
  } catch (err) {
    console.warn("MongoDB index creation notice (non-fatal):", (err as Error)?.message || err);
  }
}

export async function getMongoClient(): Promise<MongoClient> {
  const uri = process.env.MONGODB_URI || process.env.MONGO_URL;
  if (!uri || !isMongoConfigured()) throw new ApiError(503, "Configure MONGODB_URI to store templates and images.", "CONFIGURATION_REQUIRED");
  if (!globalThis.postvaneMongo || globalThis.postvaneMongo.uri !== uri) {
    const connectPromise = (async () => {
      // Connect directly with native driver first for lowest latency (0-50ms)
      let client = new MongoClient(uri, {
        connectTimeoutMS: 4000,
        serverSelectionTimeoutMS: 4000,
        maxPoolSize: 10,
        minPoolSize: 1,
        maxIdleTimeMS: 60_000,
      });

      try {
        await client.connect();
      } catch (directErr: any) {
        // Fall back to custom SRV resolver ONLY if native resolution failed (e.g. local router DNS refusal)
        const errMsg = directErr?.message || "";
        if (uri.startsWith("mongodb+srv://") && (/querySrv|ECONNREFUSED|ENOTFOUND/i.test(errMsg))) {
          console.warn("Native SRV resolution failed, attempting public DNS resolver fallback...");
          try {
            const resolvedUri = await resolveMongoUri(uri);
            client = new MongoClient(resolvedUri, {
              connectTimeoutMS: 5000,
              serverSelectionTimeoutMS: 5000,
              maxPoolSize: 10,
              minPoolSize: 1,
              maxIdleTimeMS: 60_000,
            });
            await client.connect();
          } catch (fallbackErr: any) {
            globalThis.postvaneMongo = undefined;
            await client.close().catch(() => {});
            throw new ApiError(503, `MongoDB is unavailable: ${fallbackErr?.message || "Check connection and access settings"}`, "DATABASE_UNAVAILABLE");
          }
        } else {
          globalThis.postvaneMongo = undefined;
          await client.close().catch(() => {});
          throw new ApiError(503, `MongoDB is unavailable: ${directErr?.message || "Check connection and access settings"}`, "DATABASE_UNAVAILABLE");
        }
      }

      const activeDb = process.env.MONGODB_DB_NAME ? client.db(process.env.MONGODB_DB_NAME) : client.db();
      console.log(`\x1b[32m✔ [MongoDB] Successfully connected to database: "${activeDb.databaseName}"\x1b[0m`);
      // Lazy index build in background without blocking current request
      ensureMongoIndexes(activeDb).catch(() => {});
      return client;
    })();

    globalThis.postvaneMongo = { uri, promise: connectPromise };
  }
  return globalThis.postvaneMongo.promise;
}

export async function getMongoDb(): Promise<Db> {
  const client = await getMongoClient();
  return process.env.MONGODB_DB_NAME ? client.db(process.env.MONGODB_DB_NAME) : client.db();
}

export interface StoredTemplateImageDoc {
  _id?: ObjectId;
  userId: string;
  folder: string;
  filename: string;
  contentType: string;
  size: number;
  data?: Binary;
  dataBase64?: string;
  createdAt: string;
}

export async function saveTemplateImageToMongo(input: Omit<StoredTemplateImageDoc, "_id" | "data" | "dataBase64" | "createdAt"> & { bytes: Buffer }) {
  const { bytes, ...metadata } = input;
  const createdAt = new Date().toISOString();
  const db = await getMongoDb();
  const result = await db.collection<StoredTemplateImageDoc>("template_images").insertOne({ ...metadata, data: new Binary(bytes), createdAt });
  const id = result.insertedId.toHexString();
  return { ...metadata, id, url: `${appUrl()}/api/templates/images/${id}`, createdAt };
}

export async function getTemplateImagesFromMongo(userId: string, folder?: string, limit = 50) {
  const safeLimit = Math.min(Math.max(1, limit), 100);
  const db = await getMongoDb();
  const docs = await db.collection<StoredTemplateImageDoc>("template_images")
    .find({ userId, ...(folder && folder !== "all" ? { folder } : {}) }, { projection: { data: 0, dataBase64: 0 } })
    .sort({ createdAt: -1 })
    .limit(safeLimit)
    .toArray();
  return docs.map(({ _id, ...doc }) => ({ ...doc, id: _id!.toHexString(), url: `${appUrl()}/api/templates/images/${_id!.toHexString()}` }));
}

export async function getTemplateImageByIdFromMongo(id: string) {
  if (typeof id !== "string" || !/^[0-9a-fA-F]{24}$/.test(id.trim())) return null;
  const db = await getMongoDb();
  return db.collection<StoredTemplateImageDoc>("template_images").findOne({ _id: new ObjectId(id.trim()) });
}

export async function deleteTemplateImageFromMongo(id: string, userId: string) {
  if (typeof id !== "string" || !/^[0-9a-fA-F]{24}$/.test(id.trim()) || typeof userId !== "string" || !userId.trim()) return false;
  const db = await getMongoDb();
  return (await db.collection("template_images").deleteOne({ _id: new ObjectId(id.trim()), userId: userId.trim() })).deletedCount === 1;
}
