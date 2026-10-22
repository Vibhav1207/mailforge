import crypto from "node:crypto";
import { ObjectId } from "mongodb";
import { getMongoDb } from "@/lib/mongodb";
import type { AuthenticatedUser } from "@/lib/firebase/auth-middleware";
import { ApiError } from "./errors";
import { sanitizeMongoInput } from "./mongodb-security";

export interface ApiKeyRecord {
  id: string;
  name: string;
  keyPrefix: string;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface ApiKeyCreationResult {
  id: string;
  name: string;
  key: string;
  keyPrefix: string;
  createdAt: string;
}


export async function createApiKey(
  user: AuthenticatedUser,
  rawName: string
): Promise<ApiKeyCreationResult> {
  const name = sanitizeMongoInput(rawName).trim() || "Default API Key";
  const rawSecret = crypto.randomBytes(24).toString("hex");
  const apiKey = `mf_live_${rawSecret}`;
  const keyPrefix = `${apiKey.slice(0, 11)}...${apiKey.slice(-4)}`;
  const keyHash = crypto.createHash("sha256").update(apiKey).digest("hex");
  const now = new Date().toISOString();

  const db = await getMongoDb();
  const result = await db.collection("apiKeys").insertOne({
    userId: user.uid,
    userEmail: user.email,
    name,
    keyPrefix,
    keyHash,
    createdAt: now,
    lastUsedAt: null,
  });

  return {
    id: result.insertedId.toString(),
    name,
    key: apiKey,
    keyPrefix,
    createdAt: now,
  };
}

export async function listApiKeys(user: AuthenticatedUser): Promise<ApiKeyRecord[]> {
  const db = await getMongoDb();
  const docs = await db
    .collection("apiKeys")
    .find({ userId: user.uid })
    .sort({ createdAt: -1 })
    .toArray();

  return docs.map((d: any) => ({
    id: d._id.toString(),
    name: d.name,
    keyPrefix: d.keyPrefix,
    createdAt: d.createdAt,
    lastUsedAt: d.lastUsedAt || null,
  }));
}

export async function revokeApiKey(user: AuthenticatedUser, keyId: string): Promise<boolean> {
  if (!ObjectId.isValid(keyId)) {
    throw new ApiError(400, "Invalid API key ID.", "INVALID_ID");
  }

  const db = await getMongoDb();
  const result = await db.collection("apiKeys").deleteOne({
    _id: new ObjectId(keyId),
    userId: user.uid,
  });

  return result.deletedCount > 0;
}

export async function authenticateApiKey(rawKey: string): Promise<{
  uid: string;
  email: string;
  keyName: string;
}> {
  const cleanKey = rawKey.trim().replace(/^Bearer\s+/i, "");
  if (!cleanKey.startsWith("mf_live_")) {
    throw new ApiError(401, "Invalid API key format. Expected 'mf_live_...'.", "UNAUTHORIZED");
  }

  const keyHash = crypto.createHash("sha256").update(cleanKey).digest("hex");
  const db = await getMongoDb();
  const doc: any = await db.collection("apiKeys").findOne({ keyHash });

  if (!doc) {
    throw new ApiError(401, "API key is invalid or has been revoked.", "UNAUTHORIZED");
  }

  db.collection("apiKeys").updateOne(
    { _id: doc._id },
    { $set: { lastUsedAt: new Date().toISOString() } }
  ).catch(() => { });

  return {
    uid: doc.userId,
    email: doc.userEmail || "",
    keyName: doc.name,
  };
}
