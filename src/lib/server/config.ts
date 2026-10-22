import { createHash } from "node:crypto";
import { ApiError } from "./errors";

export function configured(value?: string): boolean {
  return Boolean(value?.trim() && !/^(your[_-]|replace[_-]|change[_-])|example|^xxxx/i.test(value));
}

export function appUrl(): string {
  const value = process.env.NEXT_PUBLIC_APP_URL || (process.env.NODE_ENV !== "production" ? "http://localhost:3000" : "");
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password ||
        (process.env.NODE_ENV === "production" && url.protocol !== "https:")) throw new Error();
    return url.origin;
  } catch {
    throw new ApiError(503, "Configure NEXT_PUBLIC_APP_URL with this application's public URL.", "CONFIGURATION_REQUIRED");
  }
}

export function encryptionKey(): Buffer {
  const value = process.env.SETTINGS_ENCRYPTION_KEY || "";
  if (/^[a-fA-F0-9]{64}$/.test(value)) {
    return Buffer.from(value, "hex");
  }
  const seed = (process.env.NEXT_PUBLIC_FIREBASE_API_KEY || "") + (process.env.FIREBASE_PROJECT_ID || "mailforge_encryption_seed_2026");
  return createHash("sha256").update(seed).digest();
}

export function signingSecret(): string {
  const value = process.env.EMAIL_LINK_SECRET || "";
  if (configured(value) && value.length >= 32) {
    return value;
  }
  return createHash("sha256").update("mailforge_signing_seed_" + (process.env.FIREBASE_PROJECT_ID || "default")).digest("hex");
}

export function integerSetting(name: string, fallback: number, min: number, max: number): number {
  const value = Number(process.env[name] ?? fallback);
  return Number.isInteger(value) && value >= min && value <= max ? value : fallback;
}
