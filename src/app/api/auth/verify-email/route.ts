import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { apiError, json, parseJson } from "@/lib/server/api";
import { verifyAndConsumeToken } from "@/lib/server/tokens";
import { getMongoDb } from "@/lib/mongodb";
import { rateLimit } from "@/lib/server/rate-limit";
import { appUrl } from "@/lib/server/config";

const verifySchema = z.object({
  token: z.string().min(16).max(256),
});

export async function POST(req: NextRequest) {
  try {
    const ip = req.headers.get("x-forwarded-for")?.split(",")[0] || "anonymous";
    await rateLimit(ip, "verify-email", 10, 60_000);

    const input = await parseJson(req, verifySchema, 2048);
    const { userId, email } = await verifyAndConsumeToken(input.token, "email_verification");

    // Update user record in MongoDB
    const db = await getMongoDb();
    await db.collection("users").updateOne(
      { _id: userId as any },
      { $set: { emailVerified: true, verifiedEmail: email, updatedAt: new Date().toISOString() } }
    );

    return json({
      success: true,
      message: "Email address successfully verified.",
      userId,
      email,
    });
  } catch (error) {
    return apiError(error);
  }
}

export async function GET(req: NextRequest) {
  try {
    const token = req.nextUrl.searchParams.get("token");
    if (!token) {
      return NextResponse.redirect(`${appUrl()}/login?error=missing_verification_token`);
    }

    const { userId, email } = await verifyAndConsumeToken(token, "email_verification");

    const db = await getMongoDb();
    await db.collection("users").updateOne(
      { _id: userId as any },
      { $set: { emailVerified: true, verifiedEmail: email, updatedAt: new Date().toISOString() } }
    );

    return NextResponse.redirect(`${appUrl()}/login?verified=true`);
  } catch {
    return NextResponse.redirect(`${appUrl()}/login?error=invalid_or_expired_token`);
  }
}
