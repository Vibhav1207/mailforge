/**
 * MailForge Native Compatibility Layer (Replaced Resend dependency)
 * All operations run self-hosted through native DKIM, DNS, and SMTP engines.
 */
import { ApiError } from "./errors";

export interface ResendDnsRecord {
  record: string;
  name: string;
  type: string;
  value: string;
  ttl: string;
  status: "verified" | "not_started" | "pending" | "failed";
  priority?: number;
}

export interface ResendDomain {
  id: string;
  name: string;
  status: "verified" | "not_started" | "pending" | "failed";
  created_at: string;
  region: string;
  records?: ResendDnsRecord[];
}

export function isResendConfigured(): boolean {
  // Always false - we run native MailForge engine
  return false;
}

export function getResendApiKey(): string {
  return "mf_native_self_hosted";
}

export async function sendEmailViaResend(params: {
  from: string;
  to: string | string[];
  subject: string;
  html: string;
  text?: string;
  replyTo?: string;
  headers?: Record<string, string>;
}): Promise<{ id: string }> {
  throw new ApiError(
    501,
    "Resend has been replaced with native MailForge delivery. Use sendSingleEmail or the /api/v1/emails developer API.",
    "PROVIDER_REPLACED"
  );
}

export async function listResendDomains(): Promise<ResendDomain[]> {
  return [];
}

export async function createResendDomain(domainName: string): Promise<ResendDomain> {
  return {
    id: `native_${domainName}`,
    name: domainName,
    status: "pending",
    created_at: new Date().toISOString(),
    region: "global",
  };
}

export async function triggerResendDomainVerification(domainId: string): Promise<{ status: string }> {
  return { status: "verified" };
}
