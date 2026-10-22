import { createHash, randomUUID } from "node:crypto";
import type { SmtpConfig } from "@/types";
import { htmlToPlainText, interpolateVariables } from "@/lib/utils";
import { appUrl } from "@/lib/server/config";
import { emailSchema, headerSchema } from "@/lib/server/validation";
import { createSmtpTransport, smtpError } from "./smtp";
import { emailLinkUrl, signEmailLink, safeHttpUrl, type EmailLink } from "./links";
import { getDomainDkim } from "@/lib/server/domains";
import { assertVerifiedSenderDomain } from "@/lib/server/domain-verifier";

export interface SendSingleEmailParams {
  to: string;
  subject: string;
  html: string;
  text?: string;
  fromName: string;
  fromEmail: string;
  replyTo?: string;
  variables?: Record<string, unknown>;
  userId?: string;
  campaignId?: string;
  recipientId?: string;
  trackOpens?: boolean;
  trackClicks?: boolean;
  smtpConfig: SmtpConfig;
}

export interface SendEmailResult {
  success: boolean;
  providerMessageId?: string;
  error?: string;
  isTransient?: boolean;
  ambiguous?: boolean;
  attempts?: number;
}

export function escapeHtml(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]!));
}

function decodeHtmlUrl(value: string): string {
  return value.replace(/&amp;/gi, "&").replace(/&quot;/gi, '"').replace(/&#39;/g, "'").replace(/&#(\d+);/g, (_, number) => String.fromCodePoint(Math.min(Number(number), 0x10ffff)));
}

export function renderEmail(params: SendSingleEmailParams) {
  const to = emailSchema.parse(params.to);
  const fromEmail = emailSchema.parse(params.fromEmail);
  const fromName = headerSchema.parse(params.fromName);
  if (params.replyTo) emailSchema.parse(params.replyTo);
  const bulk = Boolean(params.userId && params.campaignId && params.recipientId);
  const link: EmailLink | undefined = bulk ? {
    purpose: "unsubscribe", userId: params.userId!, campaignId: params.campaignId!, recipientId: params.recipientId!, email: to,
  } : undefined;
  const unsubscribeUrl = link ? emailLinkUrl(link) : "";
  const variables = { ...params.variables, email: to, fromName, unsubscribeUrl };
  const subject = headerSchema.parse(interpolateVariables(params.subject, variables));
  const escaped = Object.fromEntries(Object.entries(variables).map(([key, value]) => [key, escapeHtml(value)]));
  let html = interpolateVariables(params.html, escaped);
  const origin = bulk || /(?:src|href)=["']\//i.test(html) ? appUrl() : undefined;
  html = html.replace(/\b(src|href)=(['"])(\/[^'"\s]*)\2/gi, (_, attribute, quote, path) => `${attribute}=${quote}${escapeHtml(new URL(decodeHtmlUrl(path), origin).href)}${quote}`);
  if (link && !html.includes(escapeHtml(unsubscribeUrl))) {
    const footer = `<div style="margin-top:32px;font:12px sans-serif;color:#64748b">Sent to ${escapeHtml(to)}. <a href="${escapeHtml(unsubscribeUrl)}">Unsubscribe</a> from this sender.</div>`;
    html = /<\/body>/i.test(html) ? html.replace(/<\/body>/i, `${footer}</body>`) : html + footer;
  }
  if (link && params.trackClicks !== false) {
    html = html.replace(/(<a\b[^>]*?\bhref\s*=\s*)(['"])(.*?)\2/gi, (match, prefix, quote, encodedUrl) => {
      const value = decodeHtmlUrl(encodedUrl);
      if (/^(#|mailto:|tel:)/i.test(value) || value === unsubscribeUrl || value.includes(`${origin}/api/track/`)) return match;
      const url = safeHttpUrl(value, origin);
      if (!url) return match;
      const tracked = emailLinkUrl({ ...link, purpose: "click", url });
      return `${prefix}${quote}${escapeHtml(tracked)}${quote}`;
    });
  }
  if (link && params.trackOpens !== false) {
    const pixel = `<img src="${escapeHtml(emailLinkUrl({ ...link, purpose: "open" }))}" width="1" height="1" alt="" style="border:0;width:1px;height:1px" />`;
    html = /<\/body>/i.test(html) ? html.replace(/<\/body>/i, `${pixel}</body>`) : html + pixel;
  }
  let text = params.text ? interpolateVariables(params.text, variables) : htmlToPlainText(html);
  if (link && !text.includes(unsubscribeUrl)) text += `\n\nUnsubscribe: ${unsubscribeUrl}`;
  const messageId = bulk ? `${createHash("sha256").update(`${params.userId}:${params.campaignId}:${params.recipientId}`).digest("hex")}@${fromEmail.split("@")[1]}` : `${randomUUID()}@${fromEmail.split("@")[1]}`;
  return {
    from: { name: fromName, address: fromEmail }, to, subject, html, text,
    replyTo: params.replyTo || undefined, messageId: `<${messageId}>`,
    headers: link ? {
      "List-Unsubscribe": `<${appUrl()}/api/unsubscribe?token=${encodeURIComponent(signEmailLink(link))}>`,
      "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
    } : undefined,
    disableFileAccess: true, disableUrlAccess: true,
  };
}

export async function sendSingleEmail(params: SendSingleEmailParams): Promise<SendEmailResult> {
  const message = renderEmail(params);

  // If using a custom sending domain, assert verification in production
  if (process.env.NODE_ENV === "production") {
    const isDomainVerified = await assertVerifiedSenderDomain(params.fromEmail);
    if (!isDomainVerified) {
      return {
        success: false,
        error: `Sending domain for "${params.fromEmail}" is unverified. Please add and verify it in the MailForge Domains dashboard.`,
        isTransient: false,
      };
    }
  }

  // Check if native MailForge DKIM signing key exists for this domain
  const senderDomain = params.fromEmail.split("@")[1]?.toLowerCase();
  if (senderDomain) {
    const dkim = await getDomainDkim(senderDomain);
    if (dkim) {
      (message as any).dkim = {
        domainName: dkim.domain,
        keySelector: dkim.selector,
        privateKey: dkim.privateKey,
      };
    }
  }

  let transport;
  try {
    transport = await createSmtpTransport(params.smtpConfig);
    const info = await transport.sendMail(message);
    const accepted = (info.accepted || []).some((entry: any) =>
      (typeof entry === "string" ? entry : entry?.address || "").toLowerCase() === message.to.toLowerCase()
    );
    if (!accepted) return { success: false, error: "The mail server did not accept this recipient.", isTransient: false };
    return { success: true, providerMessageId: info.messageId };
  } catch (error) {
    return { success: false, ...smtpError(error) };
  } finally {
    transport?.close();
  }
}

export async function sendEmailWithRetry(params: SendSingleEmailParams, maxRetries = 1): Promise<SendEmailResult> {
  for (let attempt = 0; ; attempt++) {
    const result = await sendSingleEmail(params);
    if (result.success || !result.isTransient || result.ambiguous || attempt >= maxRetries) return { ...result, attempts: attempt + 1 };
    await new Promise((resolve) => setTimeout(resolve, Math.min(1000 * 2 ** attempt, 5000)));
  }
}
