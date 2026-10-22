import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import nodemailer from "nodemailer";
import type { SmtpConfig } from "@/types";
import { smtpSchema } from "@/lib/server/validation";
import { ApiError } from "@/lib/server/errors";

export function isPublicAddress(address: string): boolean {
  if (isIP(address) === 4) {
    const [a, b, c] = address.split(".").map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 192 && b === 0) || (a === 192 && b === 88 && c === 99) ||
      (a === 198 && (b === 18 || b === 19 || b === 51)) || (a === 203 && b === 0 && c === 113));
  }
  // Only global IPv6 unicast; this also excludes mapped/compatible IPv4 addresses.
  return isIP(address) === 6 && /^[23][0-9a-f]{3}:/i.test(address) && !/^2001:(?:0:|db8:|10:|20:)/i.test(address) && !/^2002:/i.test(address);
}

export async function createSmtpTransport(input: SmtpConfig) {
  const config = smtpSchema.parse(input);
  if (!config.pass) throw new ApiError(400, "SMTP password is required.", "SMTP_NOT_CONFIGURED");
  const host = config.host.toLowerCase();
  // An explicitly configured development relay is useful with Mailpit. Never active in production.
  const localRelay = process.env.NODE_ENV !== "production" && process.env.SMTP_ALLOW_LOCAL === "true" && ["localhost", "127.0.0.1"].includes(host);
  if (!localRelay && ![25, 465, 587, 2525].includes(config.port)) throw new ApiError(400, "Use an SMTP port: 25, 465, 587, or 2525.", "INVALID_SMTP_PORT");
  const addresses = isIP(host) ? [{ address: host, family: isIP(host) }] : await lookup(host, { all: true });
  if (!addresses.length || (!localRelay && addresses.some(({ address }) => !isPublicAddress(address)))) {
    throw new ApiError(400, "SMTP must resolve to a public mail server.", "INVALID_SMTP_HOST");
  }
  const address = addresses.find((value) => value.family === 4) || addresses[0];
  return nodemailer.createTransport({
    host: address.address,
    port: config.port,
    secure: config.secure || config.port === 465,
    requireTLS: !localRelay,
    auth: { user: config.user, pass: host === "smtp.gmail.com" ? config.pass.replace(/\s/g, "") : config.pass },
    tls: { servername: host, minVersion: "TLSv1.2" },
    connectionTimeout: 8000,
    greetingTimeout: 8000,
    socketTimeout: 15000,
    disableFileAccess: true,
    disableUrlAccess: true,
  });
}

export function smtpError(error: unknown): { error: string; isTransient: boolean; ambiguous: boolean } {
  const { code, responseCode, command } = error as { code?: string; responseCode?: number; command?: string };
  if (code === "EAUTH" || responseCode === 535) return { error: "The mail server rejected the login. Check the SMTP password or Gmail App Password.", isTransient: false, ambiguous: false };
  if (responseCode && responseCode >= 400 && responseCode < 500) return { error: `The mail server temporarily rejected the message (${responseCode}).`, isTransient: true, ambiguous: false };
  if (responseCode && responseCode >= 500) return { error: `The mail server rejected the message (${responseCode}).`, isTransient: false, ambiguous: false };
  if (code === "EDNS" || code === "ECONNECTION" || command === "CONN" || command === "EHLO" || command === "STARTTLS") {
    return { error: "Could not connect securely to the mail server.", isTransient: true, ambiguous: false };
  }
  // SMTP cannot prove whether DATA was accepted after a connection drops. Do not resend automatically.
  if (["ETIMEDOUT", "ESOCKET", "ECONNRESET", "ECONNABORTED"].includes(code || "")) return { error: "The connection ended before delivery could be confirmed. Check the mail provider before resending.", isTransient: false, ambiguous: true };
  return { error: error instanceof ApiError ? error.message : "The mail server could not accept the message.", isTransient: false, ambiguous: false };
}
