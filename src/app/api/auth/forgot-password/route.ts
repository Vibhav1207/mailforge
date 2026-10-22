import { NextRequest } from "next/server";
import { z } from "zod";
import { apiError, json, parseJson } from "@/lib/server/api";
import { createHashedToken } from "@/lib/server/tokens";
import { getMongoDb } from "@/lib/mongodb";
import { rateLimit } from "@/lib/server/rate-limit";
import { appUrl } from "@/lib/server/config";
import { dispatchSystemEmail } from "@/lib/server/system-mailer";
import { emailSchema } from "@/lib/server/validation";

const forgotSchema = z.object({
  email: emailSchema,
});

export async function POST(req: NextRequest) {
  try {
    const ip = req.headers.get("x-forwarded-for")?.split(",")[0] || "anonymous";
    await rateLimit(ip, "forgot-password", 5, 300_000); // 5 per 5 mins per IP

    const input = await parseJson(req, forgotSchema, 2048);
    const cleanEmail = input.email.trim().toLowerCase();

    // Constant-time-like generic response to prevent account enumeration
    const genericResponse = {
      success: true,
      message: "If an account with that email exists, password reset instructions have been dispatched.",
    };

    const db = await getMongoDb();
    const user = await db.collection("users").findOne({ email: cleanEmail });

    if (!user) {
      // Do not reveal that the account does not exist
      return json(genericResponse);
    }

    const { rawToken } = await createHashedToken({
      userId: (user as any).uid || (user as any)._id?.toString() || cleanEmail,
      email: cleanEmail,
      purpose: "password_reset",
      ttlMinutes: 30, // 30 minutes
    });

    const resetUrl = `${appUrl()}/reset-password?token=${encodeURIComponent(rawToken)}`;

    await dispatchSystemEmail({
      to: cleanEmail,
      subject: "Reset your MailForge password",
      html: `
        <div style="font-family:sans-serif;max-width:540px;margin:auto;padding:24px;border:1px solid #e2e8f0;border-radius:12px;">
          <h2 style="color:#0f172a;">Password Reset Request</h2>
          <p style="color:#475569;">We received a request to reset your password. This link will expire in 30 minutes.</p>
          <div style="margin:24px 0;">
            <a href="${resetUrl}" style="background:#e11d48;color:#ffffff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block;">Reset Password</a>
          </div>
          <p style="color:#94a3b8;font-size:12px;">If you did not request a password reset, please ignore this email. Your account remains secure.</p>
        </div>
      `,
      text: `Reset your password: ${resetUrl}`,
    });

    return json({
      ...genericResponse,
      resetUrl: process.env.NODE_ENV !== "production" ? resetUrl : undefined,
    });
  } catch (error) {
    return apiError(error);
  }
}
