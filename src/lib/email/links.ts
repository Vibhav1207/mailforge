import { createHmac, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { appUrl, signingSecret } from "@/lib/server/config";
import { ApiError } from "@/lib/server/errors";

const linkSchema = z.object({
  purpose: z.enum(["unsubscribe", "open", "click"]),
  userId: z.string().min(1).max(128),
  campaignId: z.string().min(1).max(128),
  recipientId: z.string().min(1).max(128),
  email: z.string().email().max(254),
  url: z.string().max(2048).optional(),
});
export type EmailLink = z.infer<typeof linkSchema>;

export function signEmailLink(data: EmailLink): string {
  const payload = Buffer.from(JSON.stringify(linkSchema.parse(data))).toString("base64url");
  return `${payload}.${createHmac("sha256", signingSecret()).update(payload).digest("base64url")}`;
}

export function readEmailLink(token: string, purpose: EmailLink["purpose"]): EmailLink {
  const secret = signingSecret();
  try {
    if (token.length > 6000) throw new Error();
    const parts = token.split(".");
    if (parts.length !== 2) throw new Error();
    const [payload, signature] = parts;
    const expected = createHmac("sha256", secret).update(payload).digest();
    const actual = Buffer.from(signature, "base64url");
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new Error();
    const data = linkSchema.parse(JSON.parse(Buffer.from(payload, "base64url").toString("utf8")));
    if (data.purpose !== purpose) throw new Error();
    if (purpose === "click" && (!data.url || !safeHttpUrl(data.url))) throw new Error();
    return data;
  } catch {
    throw new ApiError(400, "This email link is invalid or has been modified.", "INVALID_EMAIL_LINK");
  }
}

export function safeHttpUrl(value: string, base?: string): string | null {
  try {
    const url = new URL(value, base);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.href.length > 2048) return null;
    return url.href;
  } catch { return null; }
}

export function emailLinkUrl(data: EmailLink): string {
  const path = data.purpose === "unsubscribe" ? "/unsubscribe" : `/api/track/${data.purpose}`;
  return `${appUrl()}${path}?token=${encodeURIComponent(signEmailLink(data))}`;
}
