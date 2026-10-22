import { NextRequest } from "next/server";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { apiError, json } from "@/lib/server/api";
import { createHashedToken } from "@/lib/server/tokens";
import { rateLimit } from "@/lib/server/rate-limit";
import { appUrl } from "@/lib/server/config";
import { dispatchSystemEmail } from "@/lib/server/system-mailer";

export async function POST(req: NextRequest) {
  try {
    const user = await requireUser(req);
    await rateLimit(user.uid, "send-verification", 5, 300_000); // Max 5 per 5 minutes

    const { rawToken } = await createHashedToken({
      userId: user.uid,
      email: user.email,
      purpose: "email_verification",
      ttlMinutes: 1440, // 24 hours
    });

    const verifyUrl = `${appUrl()}/api/auth/verify-email?token=${encodeURIComponent(rawToken)}`;

    await dispatchSystemEmail({
      to: user.email,
      subject: "Verify your email address for MailForge",
      html: `
        <div style="font-family:sans-serif;max-width:540px;margin:auto;padding:24px;border:1px solid #e2e8f0;border-radius:12px;">
          <h2 style="color:#0f172a;">Verify your email address</h2>
          <p style="color:#475569;">Click the button below to verify your email address. This link expires in 24 hours.</p>
          <div style="margin:24px 0;">
            <a href="${verifyUrl}" style="background:#4f46e5;color:#ffffff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block;">Verify Email Address</a>
          </div>
          <p style="color:#94a3b8;font-size:12px;">If you did not request this, you can safely ignore this email.</p>
        </div>
      `,
      text: `Verify your email: ${verifyUrl}`,
    });

    return json({
      success: true,
      message: "Verification email dispatched successfully.",
      verifyUrl: process.env.NODE_ENV !== "production" ? verifyUrl : undefined,
    });
  } catch (error) {
    return apiError(error);
  }
}
