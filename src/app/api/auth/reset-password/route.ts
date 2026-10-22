import { NextRequest } from "next/server";
import { scryptSync, randomBytes, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { apiError, json, parseJson } from "@/lib/server/api";
import { verifyAndConsumeToken } from "@/lib/server/tokens";
import { getMongoDb } from "@/lib/mongodb";
import { rateLimit } from "@/lib/server/rate-limit";

const resetPasswordSchema = z.object({
  token: z.string().min(16).max(256),
  newPassword: z
    .string()
    .min(8, "Password must be at least 8 characters long.")
    .max(128, "Password is too long.")
    .regex(/[A-Z]/, "Password must include at least one uppercase letter.")
    .regex(/[a-z]/, "Password must include at least one lowercase letter.")
    .regex(/[0-9]/, "Password must include at least one number.")
    .regex(/[^A-Za-z0-9]/, "Password must include at least one special character."),
});

/**
 * Secure password hashing using Node.js scrypt with a random 16-byte salt.
 */
export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString("hex");
  const derivedKey = scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${derivedKey}`;
}

export async function POST(req: NextRequest) {
  try {
    const ip = req.headers.get("x-forwarded-for")?.split(",")[0] || "anonymous";
    await rateLimit(ip, "reset-password", 5, 60_000);

    const input = await parseJson(req, resetPasswordSchema, 2048);

    // Verify and atomically invalidate the reset token
    const { userId } = await verifyAndConsumeToken(input.token, "password_reset");

    // Securely hash password with scrypt
    const passwordHash = hashPassword(input.newPassword);
    const now = new Date().toISOString();

    const db = await getMongoDb();

    // Update password hash and revoke active sessions
    await db.collection("users").updateOne(
      { _id: userId as any },
      {
        $set: {
          passwordHash,
          passwordUpdatedAt: now,
          sessionsRevokedAt: now,
          updatedAt: now,
        },
      }
    );

    // Invalidate all remaining reset tokens for this user
    await db.collection("passwordResetTokens").updateMany(
      { userId, used: false },
      { $set: { used: true, usedAt: new Date() } }
    );

    return json({
      success: true,
      message: "Your password has been successfully reset. Please log in with your new credentials.",
    });
  } catch (error) {
    return apiError(error);
  }
}
