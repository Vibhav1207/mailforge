import { NextRequest } from "next/server";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { apiError, json, parseJson } from "@/lib/server/api";
import { smtpSchema } from "@/lib/server/validation";
import { resolveSmtp } from "@/lib/server/settings";
import { createSmtpTransport, smtpError } from "@/lib/email/smtp";
import { rateLimit } from "@/lib/server/rate-limit";
import { ApiError } from "@/lib/server/errors";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(req: NextRequest) {
  let transport;
  try {
    const user = await requireUser(req);
    const input = await parseJson(req, smtpSchema, 8000);
    await rateLimit(user.uid, "smtp-verify", 10);
    const smtp = await resolveSmtp(user, input);
    transport = await createSmtpTransport(smtp);
    try { await transport.verify(); }
    catch (error) { throw new ApiError(400, smtpError(error).error, "SMTP_VERIFICATION_FAILED"); }
    return json({ success: true, message: `Connected to ${smtp.host} as ${smtp.user}. Save Settings to use this account for campaigns.` });
  } catch (error) { return apiError(error); }
  finally { transport?.close(); }
}
