import { NextRequest } from "next/server";
import { z } from "zod";
import { ObjectId } from "mongodb";
import { getMongoDb } from "@/lib/mongodb";
import { apiError, json, parseJson } from "@/lib/server/api";
import { authenticateApiKey } from "@/lib/server/api-keys";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { resolveSmtp } from "@/lib/server/settings";
import { sendSingleEmail } from "@/lib/email/provider";
import { rateLimit } from "@/lib/server/rate-limit";
import { ApiError } from "@/lib/server/errors";
import { emailSchema } from "@/lib/server/validation";

const emailDispatchSchema = z.object({
  from: z.string().min(3).max(255),
  to: z.union([emailSchema, z.array(emailSchema).min(1).max(50)]),
  subject: z.string().min(1).max(500),
  html: z.string().min(1).max(1_000_000),
  text: z.string().max(500_000).optional(),
  reply_to: z.string().optional(),
  replyTo: z.string().optional(),
  headers: z.record(z.string()).optional(),
  tags: z.array(z.object({ name: z.string(), value: z.string() })).optional(),
});

function parseFromAddress(raw: string): { name: string; address: string } {
  const match = raw.match(/^(?:["']?([^"']*)["']?\s+<)?([^<>@\s]+@[^<>@\s]+)>?$/);
  if (!match) {
    return { name: "MailForge Sender", address: raw.trim().toLowerCase() };
  }
  const name = match[1]?.trim() || "MailForge Sender";
  const address = match[2]?.trim().toLowerCase();
  return { name, address };
}

async function resolveCaller(req: NextRequest): Promise<{ uid: string; email: string }> {
  const authHeader = req.headers.get("authorization") || req.headers.get("x-api-key");
  if (authHeader && (authHeader.startsWith("Bearer mf_live_") || authHeader.startsWith("mf_live_"))) {
    return authenticateApiKey(authHeader);
  }

  // Fallback to cookie-based authenticated dashboard user
  try {
    const user = await requireUser(req);
    return { uid: user.uid, email: user.email };
  } catch {
    throw new ApiError(401, "Missing or invalid API key. Provide Authorization: Bearer mf_live_...", "UNAUTHORIZED");
  }
}

export async function POST(req: NextRequest) {
  try {
    const caller = await resolveCaller(req);
    await rateLimit(caller.uid, "api-dispatch", 100, 60_000); // 100/min

    const input = await parseJson(req, emailDispatchSchema, 1_048_576);
    const { name: fromName, address: fromEmail } = parseFromAddress(input.from);
    const recipients = Array.isArray(input.to) ? input.to : [input.to];
    const replyTo = input.reply_to || input.replyTo;

    // Resolve caller's SMTP credentials
    const smtpConfig = await resolveSmtp({
      uid: caller.uid,
      email: caller.email,
    });

    const db = await getMongoDb();
    const dispatchId = `email_${new ObjectId().toString()}`;
    const now = new Date().toISOString();

    // Dispatch to each recipient
    const sendResults = await Promise.all(
      recipients.map((toEmail) =>
        sendSingleEmail({
          to: toEmail,
          fromName,
          fromEmail,
          subject: input.subject,
          html: input.html,
          text: input.text,
          replyTo,
          userId: caller.uid,
          smtpConfig,
        })
      )
    );

    const firstFailure = sendResults.find((r) => !r.success);
    const overallSuccess = sendResults.every((r) => r.success);

    // Record the API email dispatch
    await db.collection("apiDispatches").insertOne({
      id: dispatchId,
      userId: caller.uid,
      userEmail: caller.email,
      from: `${fromName} <${fromEmail}>`,
      fromEmail,
      to: recipients,
      subject: input.subject,
      status: overallSuccess ? "sent" : "failed",
      error: firstFailure?.error || null,
      providerMessageId: sendResults[0]?.providerMessageId || null,
      tags: input.tags || [],
      createdAt: now,
    });

    if (!overallSuccess && firstFailure) {
      throw new ApiError(400, `Delivery failed: ${firstFailure.error}`, "DELIVERY_FAILED");
    }

    return json(
      {
        id: dispatchId,
        from: `${fromName} <${fromEmail}>`,
        to: recipients,
        created_at: now,
        status: "sent",
      },
      200
    );
  } catch (error) {
    return apiError(error);
  }
}

export async function GET(req: NextRequest) {
  try {
    const caller = await resolveCaller(req);
    const db = await getMongoDb();

    const emails = await db
      .collection("apiDispatches")
      .find({ userId: caller.uid })
      .sort({ createdAt: -1 })
      .limit(50)
      .toArray();

    return json({
      data: emails.map((e: any) => ({
        id: e.id || e._id.toString(),
        from: e.from,
        to: e.to,
        subject: e.subject,
        status: e.status,
        created_at: e.createdAt,
      })),
    });
  } catch (error) {
    return apiError(error);
  }
}
