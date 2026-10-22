import { z } from "zod";

export const idSchema = z.string().regex(/^[a-zA-Z0-9_-]{1,128}$/, "Invalid resource ID.");
export const emailSchema = z.string().trim().toLowerCase().max(254).email();
export const headerSchema = z.string().max(998).refine((value) => !/[\r\n\0]/.test(value), "Email headers cannot contain line breaks.");
export const optionalEmailSchema = z.union([emailSchema, z.literal("")]).optional();
export const folderSchema = z.string().trim().min(1).max(80).default("general");
export const smtpSchema = z.object({
  host: z.string().trim().min(1).max(253).regex(/^[a-zA-Z0-9.-]+$/, "Enter a hostname without a URL or port."),
  port: z.number().int().min(1).max(65535),
  secure: z.boolean(),
  user: z.string().trim().min(1).max(320).refine((value) => !/[\r\n\0]/.test(value)),
  pass: z.string().max(2048).default(""),
});
export const recipientSchema = z.object({
  id: idSchema.optional(),
  email: emailSchema,
  firstName: z.string().max(200).optional(),
  lastName: z.string().max(200).optional(),
  company: z.string().max(300).optional(),
  customFields: z.record(z.string().regex(/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/), z.string().max(2000)).refine((fields) => Object.keys(fields).length <= 50, "At most 50 custom fields are allowed.").optional(),
});
export const campaignContentSchema = z.object({
  name: z.string().trim().min(1).max(200),
  subject: headerSchema,
  fromName: headerSchema,
  fromEmail: z.union([emailSchema, z.literal("")]),
  replyTo: optionalEmailSchema,
  htmlContent: z.string().max(300_000),
  textContent: z.string().max(300_000).optional(),
  trackOpens: z.boolean().optional(),
  trackClicks: z.boolean().optional(),
});
export const sendCampaignSchema = campaignContentSchema.extend({
  campaignId: idSchema,
  subject: headerSchema.refine((value) => Boolean(value.trim()), "Subject is required."),
  htmlContent: z.string().min(1).max(300_000),
  idempotencyKey: idSchema,
  recipients: z.array(recipientSchema).min(1).max(5000),
  scheduledFor: z.string().datetime().nullable().optional(),
});
export const draftSchema = campaignContentSchema.extend({
  id: idSchema,
  status: z.literal("draft"),
  recipientCount: z.number().int().min(0).max(5000).default(0),
  draftRecipients: z.array(recipientSchema).max(5000).optional(),
  templateId: idSchema.optional(),
});
export const contactSchema = recipientSchema.extend({
  id: idSchema,
  status: z.enum(["active", "unsubscribed", "suppressed"]),
  listIds: z.array(idSchema).max(50).optional(),
  tags: z.array(z.string().max(80)).max(50).optional(),
  suppressionReason: z.string().max(500).optional(),
});
export const templateSchema = z.object({
  id: idSchema.optional(),
  name: z.string().trim().min(1).max(200),
  subject: headerSchema,
  category: z.enum(["outreach", "event", "announcement", "followup", "newsletter", "custom"]).default("custom"),
  description: z.string().max(2000).default(""),
  folder: folderSchema,
  imageUrl: z.union([z.string().url().refine((value) => /^https?:\/\//i.test(value)), z.literal("")]).optional(),
  htmlContent: z.string().min(1).max(300_000),
  textContent: z.string().max(300_000).optional(),
});
export const settingsSchema = z.object({
  defaultFromName: headerSchema.optional(),
  defaultFromEmail: optionalEmailSchema,
  defaultReplyTo: optionalEmailSchema,
  timezone: z.string().max(80).refine((value) => { try { new Intl.DateTimeFormat("en", { timeZone: value }); return true; } catch { return false; } }, "Invalid timezone.").optional(),
  trackOpens: z.boolean().optional(),
  trackClicks: z.boolean().optional(),
  autoAppendUnsubscribe: z.boolean().optional(),
  deliveryMethod: z.enum(["gmail_app_password", "custom_smtp"]).optional(),
  gmail: z.object({ email: z.union([emailSchema, z.literal("")]), appPassword: z.string().max(2048).optional() }).optional(),
  smtp: smtpSchema.optional(),
});
