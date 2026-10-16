import nodemailer, { Transporter } from "nodemailer";
import { interpolateVariables, htmlToPlainText, isValidEmail } from "@/lib/utils";
import { SmtpConfig } from "@/types";

// Environment Gmail Google App Password configuration
const GMAIL_USER = process.env.GMAIL_USER || "";
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || "";

// Environment SMTP configuration (Self-hosted custom sending engine)
const SMTP_HOST = process.env.SMTP_HOST || "";
const SMTP_PORT = parseInt(process.env.SMTP_PORT || "587", 10);
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = process.env.SMTP_PASS || "";
const SMTP_SECURE = process.env.SMTP_SECURE === "true" || SMTP_PORT === 465;

const DEFAULT_FROM_EMAIL =
  process.env.GMAIL_USER ||
  process.env.FROM_EMAIL ||
  process.env.SMTP_USER ||
  "";
const DEFAULT_FROM_NAME = process.env.FROM_NAME || "MailForge Dispatcher";
const DEFAULT_REPLY_TO = process.env.REPLY_TO || "";
const APP_URL = process.env.NEXT_PUBLIC_APP_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:3000");

export const isGmailConfigured = Boolean(
  GMAIL_USER &&
  GMAIL_APP_PASSWORD &&
  !GMAIL_APP_PASSWORD.includes("example")
);

export const isSmtpConfigured = Boolean(
  (SMTP_HOST && SMTP_USER && SMTP_PASS) || isGmailConfigured
);

// Cached transporters
let cachedTransporter: Transporter | null = null;
let cachedGmailTransporter: Transporter | null = null;

export function getCustomTransporter(customSmtp?: SmtpConfig): Transporter | null {
  if (customSmtp?.user && customSmtp?.pass) {
    const isGmail =
      customSmtp.host?.includes("gmail") ||
      customSmtp.user?.toLowerCase().endsWith("@gmail.com");

    const cleanedPass = customSmtp.pass.replace(/\s+/g, "");

    if (isGmail) {
      return nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: customSmtp.user.trim(),
          pass: cleanedPass,
        },
        connectionTimeout: 20000,
        greetingTimeout: 10000,
      });
    }

    return nodemailer.createTransport({
      host: customSmtp.host || "smtp.gmail.com",
      port: customSmtp.port || 587,
      secure: customSmtp.secure || customSmtp.port === 465,
      auth: {
        user: customSmtp.user.trim(),
        pass: cleanedPass,
      },
      connectionTimeout: 20000,
      greetingTimeout: 10000,
    });
  }

  // Fallback to environment Gmail configuration
  if (isGmailConfigured) {
    if (!cachedGmailTransporter) {
      cachedGmailTransporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: GMAIL_USER.trim(),
          pass: GMAIL_APP_PASSWORD.replace(/\s+/g, ""),
        },
        connectionTimeout: 20000,
        greetingTimeout: 10000,
      });
    }
    return cachedGmailTransporter;
  }

  // Fallback to environment custom SMTP
  if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
    if (!cachedTransporter) {
      cachedTransporter = nodemailer.createTransport({
        host: SMTP_HOST,
        port: SMTP_PORT,
        secure: SMTP_SECURE,
        auth: {
          user: SMTP_USER.trim(),
          pass: SMTP_PASS.replace(/\s+/g, ""),
        },
        connectionTimeout: 20000,
        greetingTimeout: 10000,
      });
    }
    return cachedTransporter;
  }

  return null;
}

export interface SendSingleEmailParams {
  to: string;
  subject: string;
  html: string;
  text?: string;
  fromName?: string;
  fromEmail?: string;
  replyTo?: string;
  variables?: Record<string, any>;
  campaignId?: string;
  recipientId?: string;
  idempotencyKey?: string;
  trackOpens?: boolean;
  trackClicks?: boolean;
  smtpConfig?: SmtpConfig;
}

export interface SendEmailResult {
  success: boolean;
  providerMessageId?: string;
  error?: string;
  isTransient?: boolean;
}

export function isRetryableError(errorMsg?: string): boolean {
  if (!errorMsg) return false;
  const lower = errorMsg.toLowerCase();
  return (
    lower.includes("rate limit") ||
    lower.includes("429") ||
    lower.includes("timeout") ||
    lower.includes("500") ||
    lower.includes("502") ||
    lower.includes("503") ||
    lower.includes("econnreset") ||
    lower.includes("etimedout") ||
    lower.includes("network") ||
    lower.includes("retry")
  );
}

export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Rewrites HTML links to pass through the click tracker endpoint
 */
function rewriteLinksForClickTracking(html: string, campaignId: string, recipientId: string): string {
  if (!campaignId || !recipientId) return html;
  return html.replace(/<a\s+(?:[^>]*?\s+)?href=(["'])(.*?)\1/gi, (match, quote, url) => {
    // Avoid rewriting unsubscribe links, mailto, tel, or fragment hashes
    if (
      url.startsWith("#") ||
      url.startsWith("mailto:") ||
      url.startsWith("tel:") ||
      url.includes("/unsubscribe") ||
      url.includes("/api/track")
    ) {
      return match;
    }
    const trackingUrl = `${APP_URL}/api/track/click?cid=${encodeURIComponent(campaignId)}&rid=${encodeURIComponent(recipientId)}&url=${encodeURIComponent(url)}`;
    return match.replace(url, trackingUrl);
  });
}

/**
 * Sends a single email with unlimited capacity, open tracking, and link click tracking
 */
export async function sendSingleEmail(params: SendSingleEmailParams): Promise<SendEmailResult> {
  const {
    to,
    subject,
    html,
    text,
    fromName = DEFAULT_FROM_NAME,
    fromEmail = DEFAULT_FROM_EMAIL,
    replyTo = DEFAULT_REPLY_TO,
    variables = {},
    campaignId,
    recipientId,
    trackOpens = true,
    trackClicks = true,
    smtpConfig,
  } = params;

  if (!isValidEmail(to)) {
    return {
      success: false,
      error: `Invalid recipient email format: ${to}`,
      isTransient: false,
    };
  }

  const unsubscribeUrl = `${APP_URL}/unsubscribe?email=${encodeURIComponent(to)}&cid=${encodeURIComponent(campaignId || "")}`;
  const mergedVariables = {
    ...variables,
    email: to,
    fromName,
    unsubscribeUrl,
  };

  const finalSubject = interpolateVariables(subject, mergedVariables);
  let finalHtml = interpolateVariables(html, mergedVariables);

  // 1. Mandatory compliance unsubscribe footer if missing
  if (!finalHtml.includes(unsubscribeUrl) && !finalHtml.includes("unsubscribe")) {
    finalHtml += `
      <div style="margin-top: 32px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #64748b; font-family: sans-serif; text-align: center;">
        Sent to ${to}. <a href="${unsubscribeUrl}" style="color: #64748b; text-decoration: underline;">Unsubscribe</a> from future communications.
      </div>
    `;
  }

  // 2. Click tracking link rewriting
  if (trackClicks && campaignId && recipientId) {
    finalHtml = rewriteLinksForClickTracking(finalHtml, campaignId, recipientId);
  }

  // 3. Open tracking invisible 1x1 pixel injection
  if (trackOpens && campaignId && recipientId) {
    const openPixelUrl = `${APP_URL}/api/track/open?cid=${encodeURIComponent(campaignId)}&rid=${encodeURIComponent(recipientId)}`;
    finalHtml += `<img src="${openPixelUrl}" width="1" height="1" alt="" style="display:none;width:1px;height:1px;border:0;" />`;
  }

  const finalPlainText = text ? interpolateVariables(text, mergedVariables) : htmlToPlainText(finalHtml);
  const formattedFrom = `"${fromName}" <${fromEmail}>`;

  // PRIMARY SERVICE: Native Gmail / Custom SMTP Engine
  const smtpTransport = getCustomTransporter(smtpConfig);
  if (smtpTransport) {
    try {
      const info = await smtpTransport.sendMail({
        from: formattedFrom,
        to,
        subject: finalSubject,
        html: finalHtml,
        text: finalPlainText,
        replyTo: replyTo || undefined,
        headers: {
          "X-MailForge-Engine": "Gmail-AppPassword-SMTP",
          "X-MailForge-Campaign": campaignId || "direct",
          "X-MailForge-Recipient": recipientId || "direct",
        },
      });

      return {
        success: true,
        providerMessageId: info.messageId || `gmail_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
      };
    } catch (err: any) {
      const errorMsg = err?.message || String(err);
      return {
        success: false,
        error: errorMsg,
        isTransient: isRetryableError(errorMsg),
      };
    }
  }

  // If no SMTP / Gmail credentials could be resolved
  return {
    success: false,
    error: "No SMTP or Gmail App Password configuration provided. Please configure your Gmail or SMTP settings in Settings.",
    isTransient: false,
  };
}

export async function sendEmailWithRetry(
  params: SendSingleEmailParams,
  maxRetries = 3
): Promise<SendEmailResult> {
  let attempt = 0;
  let lastError = "";

  while (attempt <= maxRetries) {
    const result = await sendSingleEmail(params);
    if (result.success) {
      return result;
    }

    lastError = result.error || "Unknown delivery error";

    if (!result.isTransient || attempt === maxRetries) {
      return {
        success: false,
        error: lastError,
        isTransient: false,
      };
    }

    attempt++;
    // Exponential backoff with jitter: 200ms, 400ms, 800ms...
    const backoff = Math.min(1000 * Math.pow(2, attempt) + Math.random() * 200, 5000);
    await sleep(backoff);
  }

  return {
    success: false,
    error: lastError || "Exceeded maximum retry attempts",
    isTransient: false,
  };
}

/**
 * Bulk batch execution with zero sending quotas
 */
export async function sendBatchEmails(
  recipients: Array<{
    recipientId: string;
    email: string;
    firstName?: string;
    lastName?: string;
    company?: string;
    customFields?: Record<string, string>;
  }>,
  campaign: {
    id: string;
    subject: string;
    htmlContent: string;
    textContent?: string;
    fromName: string;
    fromEmail: string;
    replyTo?: string;
    trackOpens?: boolean;
    trackClicks?: boolean;
    smtpConfig?: SmtpConfig;
  },
  onProgress?: (stats: { sent: number; failed: number; total: number }) => Promise<void> | void,
  options: { batchSize?: number; delayBetweenBatchesMs?: number } = {}
): Promise<{
  results: Array<{ recipientId: string; email: string; success: boolean; providerMessageId?: string; error?: string }>;
  stats: { total: number; sent: number; failed: number };
}> {
  const batchSize = options.batchSize || parseInt(process.env.BATCH_SIZE || "30", 10);
  const delayMs = options.delayBetweenBatchesMs || parseInt(process.env.BATCH_DELAY_MS || "200", 10);

  const results: Array<{ recipientId: string; email: string; success: boolean; providerMessageId?: string; error?: string }> = [];
  let sentCount = 0;
  let failedCount = 0;

  for (let i = 0; i < recipients.length; i += batchSize) {
    const chunk = recipients.slice(i, i + batchSize);

    const chunkPromises = chunk.map(async (r) => {
      const sendResult = await sendEmailWithRetry({
        to: r.email,
        subject: campaign.subject,
        html: campaign.htmlContent,
        text: campaign.textContent,
        fromName: campaign.fromName,
        fromEmail: campaign.fromEmail,
        replyTo: campaign.replyTo,
        campaignId: campaign.id,
        recipientId: r.recipientId,
        trackOpens: campaign.trackOpens !== false,
        trackClicks: campaign.trackClicks !== false,
        smtpConfig: campaign.smtpConfig,
        variables: {
          firstName: r.firstName,
          lastName: r.lastName,
          company: r.company,
          ...(r.customFields || {}),
        },
      });

      return {
        recipientId: r.recipientId,
        email: r.email,
        success: sendResult.success,
        providerMessageId: sendResult.providerMessageId,
        error: sendResult.error,
      };
    });

    const chunkResults = await Promise.all(chunkPromises);

    for (const res of chunkResults) {
      results.push(res);
      if (res.success) {
        sentCount++;
      } else {
        failedCount++;
      }
    }

    if (onProgress) {
      await onProgress({ sent: sentCount, failed: failedCount, total: recipients.length });
    }

    if (i + batchSize < recipients.length) {
      await sleep(delayMs);
    }
  }

  return {
    results,
    stats: {
      total: recipients.length,
      sent: sentCount,
      failed: failedCount,
    },
  };
}
