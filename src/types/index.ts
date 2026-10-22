export type ContactStatus = "active" | "unsubscribed" | "suppressed";

export interface Contact {
  id: string;
  userId: string;
  email: string;
  firstName?: string;
  lastName?: string;
  company?: string;
  listIds?: string[];
  tags?: string[];
  customFields?: Record<string, string>;
  status: ContactStatus;
  suppressionReason?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ContactList {
  id: string;
  userId: string;
  name: string;
  description?: string;
  contactCount: number;
  createdAt: string;
}

export type CampaignStatus =
  | "draft"
  | "scheduled"
  | "queued"
  | "sending"
  | "completed"
  | "completed_with_errors"
  | "failed"
  | "cancelled";

export interface CampaignStats {
  total: number;
  sent: number;
  delivered: number;
  bounced: number;
  failed: number;
  unsubscribed: number;
  opened?: number;
  clicked?: number;
  suppressed?: number;
}

export interface Campaign {
  id: string;
  userId: string;
  name: string;
  subject: string;
  fromName: string;
  fromEmail: string;
  replyTo?: string;
  htmlContent: string;
  textContent?: string;
  templateId?: string;
  recipientCount: number;
  status: CampaignStatus;
  scheduledFor?: string | null;
  stats: CampaignStats;
  errorMessage?: string;
  idempotencyKey?: string;
  createdAt: string;
  updatedAt: string;
  completedAt?: string | null;
  trackOpens?: boolean;
  trackClicks?: boolean;
  draftRecipients?: Array<{ id?: string; email: string; firstName?: string; lastName?: string; company?: string; customFields?: Record<string, string> }>;
}

export type RecipientStatus =
  | "queued"
  | "sending"
  | "sent"
  | "delivered"
  | "bounced"
  | "failed"
  | "suppressed"
  | "unknown"
  | "cancelled";

export interface CampaignRecipient {
  id: string;
  campaignId: string;
  userId: string;
  email: string;
  firstName?: string;
  lastName?: string;
  company?: string;
  customFields?: Record<string, string>;
  status: RecipientStatus;
  providerMessageId?: string;
  error?: string;
  attempts: number;
  sentAt?: string | null;
  deliveredAt?: string | null;
  openedAt?: string | null;
  clickedAt?: string | null;
  openCount?: number;
  clickCount?: number;
  retryable?: boolean;
  nextAttemptAt?: string | null;
  unsubscribedAt?: string | null;
}

export interface EmailTemplate {
  id: string;
  userId?: string | null; // null for built-in system templates
  name: string;
  description?: string;
  subject: string;
  category: "outreach" | "event" | "announcement" | "followup" | "newsletter" | "custom";
  imageUrl?: string; // Optional template header/banner image stored in MongoDB or URL
  folder?: string;   // Optional template folder categorization (e.g. "Newsletters", "Banners")
  htmlContent: string;
  textContent?: string;
  isDefault?: boolean;
  createdAt: string;
}

export interface TemplateImage {
  id: string;
  userId: string;
  folder?: string;
  filename: string;
  contentType: string;
  size: number;
  url: string;
  createdAt: string;
}

export interface EmailEvent {
  id: string;
  campaignId: string;
  recipientId?: string;
  userId: string;
  event: "sent" | "delivered" | "bounced" | "complaint" | "opened" | "clicked" | "failed";
  providerMessageId?: string;
  email: string;
  timestamp: string;
  details?: Record<string, any>;
}

export interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean;
  user: string;
  pass: string;
  hasPassword?: boolean;
}

export interface GmailConfig {
  email: string;
  appPassword?: string;
  isConnected?: boolean;
  hasAppPassword?: boolean;
}

export interface UserSettings {
  defaultFromName: string;
  defaultFromEmail: string;
  defaultReplyTo: string;
  timezone: string;
  trackOpens: boolean;
  trackClicks: boolean;
  autoAppendUnsubscribe: boolean;
  deliveryMethod?: "gmail_app_password" | "custom_smtp";
  gmail?: GmailConfig;
  smtp?: SmtpConfig;
}

export interface UserProfile {
  uid: string;
  email: string;
  displayName: string;
  photoURL?: string;
  settings: UserSettings;
  createdAt: string;
  updatedAt: string;
}

export interface SendTestEmailRequest {
  to: string;
  subject: string;
  htmlContent: string;
  textContent?: string;
  fromName?: string;
  fromEmail?: string;
  replyTo?: string;
  smtpConfig?: SmtpConfig;
}

export interface SendCampaignOptions {
  batchSize?: number;
  batchDelayMs?: number;
}

