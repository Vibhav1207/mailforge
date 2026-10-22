import { createHash } from "node:crypto";
import { getAdminDb, isFirebaseAdminConfigured } from "@/lib/firebase/admin";
import { ApiError } from "./errors";

const memoryLimits = new Map<string, { count: number; resetAt: number }>();

export async function rateLimit(userId: string, action: string, maximum: number, windowMs = 60_000): Promise<void> {
  const now = Date.now();
  const key = createHash("sha256").update(`${userId}:${action}`).digest("hex");

  if (!isFirebaseAdminConfigured()) {
    const existing = memoryLimits.get(key);
    const current = existing && existing.resetAt > now ? existing.count : 0;
    if (current >= maximum) throw new ApiError(429, "Too many requests. Please try again in a minute.", "RATE_LIMITED");
    const resetAt = existing && existing.resetAt > now ? existing.resetAt : now + windowMs;
    memoryLimits.set(key, { count: current + 1, resetAt });
    return;
  }

  const db = getAdminDb();
  const ref = db.collection("rateLimits").doc(key);
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const data = snap.data();
    const current = data && data.resetAt > now ? data.count : 0;
    if (current >= maximum) throw new ApiError(429, "Too many requests. Please try again in a minute.", "RATE_LIMITED");
    const resetAt = data && data.resetAt > now ? data.resetAt : now + windowMs;
    tx.set(ref, { count: current + 1, resetAt, expiresAt: new Date(resetAt) });
  });
}
