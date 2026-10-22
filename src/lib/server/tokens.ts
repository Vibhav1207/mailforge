import { randomBytes, createHash } from "node:crypto";
import { getMongoDb } from "@/lib/mongodb";
import { ApiError } from "./errors";

export interface VerificationTokenDoc {
  tokenHash: string;
  userId: string;
  email: string;
  purpose: "email_verification" | "password_reset";
  expiresAt: Date;
  used: boolean;
  createdAt: Date;
  usedAt?: Date;
}

/**
 * Generates a cryptographically secure, high-entropy random token.
 * Uses Node.js crypto.randomBytes (32 bytes = 256 bits of entropy).
 */
export function generateSecureToken(byteLength = 32): string {
  return randomBytes(byteLength).toString("hex");
}

/**
 * Computes a secure SHA-256 hash of a token for storage and lookup.
 * Plaintext tokens are NEVER stored in the database.
 */
export function hashToken(token: string): string {
  if (typeof token !== "string" || !token.trim()) {
    throw new ApiError(400, "Invalid token provided.", "INVALID_TOKEN");
  }
  return createHash("sha256").update(token.trim()).digest("hex");
}

/**
 * Creates and persists a hashed single-use verification token in MongoDB.
 * Automatically invalidates any existing unused tokens for the same user and purpose.
 */
export async function createHashedToken(params: {
  userId: string;
  email: string;
  purpose: "email_verification" | "password_reset";
  ttlMinutes?: number;
}): Promise<{ rawToken: string; expiresAt: Date }> {
  const { userId, email, purpose, ttlMinutes = purpose === "email_verification" ? 1440 : 30 } = params;
  const rawToken = generateSecureToken(32);
  const tokenHash = hashToken(rawToken);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttlMinutes * 60 * 1000);

  const db = await getMongoDb();
  const collectionName = purpose === "email_verification" ? "emailVerificationTokens" : "passwordResetTokens";
  const collection = db.collection<VerificationTokenDoc>(collectionName);

  // Invalidate any prior unused tokens for this user and purpose
  await collection.updateMany(
    { userId, purpose, used: false },
    { $set: { used: true, usedAt: now } }
  );

  // Save the new hashed token
  await collection.insertOne({
    tokenHash,
    userId,
    email: email.trim().toLowerCase(),
    purpose,
    expiresAt,
    used: false,
    createdAt: now,
  });

  return { rawToken, expiresAt };
}

/**
 * Verifies and consumes a single-use token from MongoDB.
 * If valid and unexpired, marks it as used and returns the associated token document.
 */
export async function verifyAndConsumeToken(
  rawToken: string,
  purpose: "email_verification" | "password_reset"
): Promise<{ userId: string; email: string }> {
  if (typeof rawToken !== "string" || rawToken.trim().length < 16) {
    throw new ApiError(400, "Invalid or malformed verification token.", "INVALID_TOKEN");
  }

  const tokenHash = hashToken(rawToken);
  const db = await getMongoDb();
  const collectionName = purpose === "email_verification" ? "emailVerificationTokens" : "passwordResetTokens";
  const collection = db.collection<VerificationTokenDoc>(collectionName);

  const doc = await collection.findOne({ tokenHash, purpose });

  if (!doc) {
    throw new ApiError(400, "This verification link is invalid or has expired.", "TOKEN_NOT_FOUND");
  }

  if (doc.used) {
    throw new ApiError(400, "This verification link has already been used.", "TOKEN_ALREADY_USED");
  }

  const now = new Date();
  if (new Date(doc.expiresAt) < now) {
    // Invalidate expired token
    await collection.updateOne({ _id: doc.tokenHash as any }, { $set: { used: true, usedAt: now } });
    throw new ApiError(400, "This verification link has expired. Please request a new one.", "TOKEN_EXPIRED");
  }

  // Atomically mark token as used
  const updateResult = await collection.findOneAndUpdate(
    { tokenHash, purpose, used: false },
    { $set: { used: true, usedAt: now } },
    { returnDocument: "after" }
  );

  if (!updateResult) {
    throw new ApiError(400, "This verification token was already consumed.", "TOKEN_ALREADY_USED");
  }

  return { userId: doc.userId, email: doc.email };
}
