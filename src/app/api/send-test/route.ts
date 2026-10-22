import { NextRequest } from "next/server";
import { z } from "zod";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { sendEmailWithRetry } from "@/lib/email/provider";
import { apiError, json, parseJson } from "@/lib/server/api";
import { emailSchema, headerSchema, optionalEmailSchema, smtpSchema } from "@/lib/server/validation";
import { resolveSmtp } from "@/lib/server/settings";
import { rateLimit } from "@/lib/server/rate-limit";
import { ApiError } from "@/lib/server/errors";

export const runtime = "nodejs";
export const maxDuration = 60;
const schema = z.object({
  to: emailSchema.optional(), subject: headerSchema.default("Email Preview"),
  htmlContent: z.string().min(1).max(300_000), textContent: z.string().max(300_000).optional(),
  fromName: headerSchema.default("MailForge Preview"), fromEmail: optionalEmailSchema,
  replyTo: optionalEmailSchema, smtpConfig: smtpSchema.optional(),
});

export async function POST(req: NextRequest) {
  try {
    const user = await requireUser(req);
    const input = await parseJson(req, schema, 650_000);
    const to = input.to || user.email;
    if (to !== user.email) throw new ApiError(400, "Test messages can only be sent to your signed-in email address.", "INVALID_TEST_RECIPIENT");
    await rateLimit(user.uid, "send-test", 5);
    const smtp = await resolveSmtp(user, input.smtpConfig);
    const fromEmail = input.fromEmail || (smtp.host === "smtp.gmail.com" ? smtp.user : process.env.FROM_EMAIL || user.email);
    if (smtp.host === "smtp.gmail.com" && fromEmail.toLowerCase() !== smtp.user.toLowerCase()) throw new ApiError(400, "The From address must match the connected Gmail account.", "INVALID_SENDER");
    const result = await sendEmailWithRetry({
      to, subject: `[TEST] ${input.subject}`, html: input.htmlContent, text: input.textContent,
      fromName: input.fromName, fromEmail, replyTo: input.replyTo, smtpConfig: smtp,
      variables: { firstName: user.name?.split(" ")[0] || "Recipient", lastName: user.name?.split(" ").slice(1).join(" ") || "", company: "" },
    }, 0);
    if (!result.success) throw new ApiError(502, result.error || "The mail server did not accept the message.", result.ambiguous ? "DELIVERY_UNKNOWN" : "SMTP_SEND_FAILED");
    return json({ success: true, providerMessageId: result.providerMessageId, sentTo: to });
  } catch (error) { return apiError(error); }
}
