import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// RFC 5322 compliant email regex check
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

export function isValidEmail(email: string): boolean {
  if (!email || typeof email !== "string") return false;
  const trimmed = email.trim();
  if (trimmed.length > 254) return false;
  return EMAIL_REGEX.test(trimmed);
}

// Parse string of emails separated by commas, semicolons, spaces, newlines
export function parseEmailList(raw: string): { valid: string[]; invalid: string[]; duplicates: number } {
  if (!raw) return { valid: [], invalid: [], duplicates: 0 };

  const tokens = raw
    .split(/[\r\n,; \t]+/)
    .map((t) => t.trim().toLowerCase())
    .filter(Boolean);

  const validSet = new Set<string>();
  const invalid: string[] = [];
  let duplicates = 0;

  for (const token of tokens) {
    // Strip surrounding brackets <user@domain.com>
    const cleaned = token.replace(/^<|>$/g, "").trim();
    if (!cleaned) continue;

    if (isValidEmail(cleaned)) {
      if (validSet.has(cleaned)) {
        duplicates++;
      } else {
        validSet.add(cleaned);
      }
    } else {
      invalid.push(cleaned);
    }
  }

  return {
    valid: Array.from(validSet),
    invalid,
    duplicates,
  };
}

// Template variable interpolation {{firstName}}, {{company}}, etc.
export function interpolateVariables(
  content: string,
  variables: Record<string, any>
): string {
  if (!content) return "";
  return content.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (match, key) => {
    let val = variables[key];
    if (val === undefined && variables.customFields && typeof variables.customFields === "object") {
      val = variables.customFields[key];
    }
    if (val !== undefined && val !== null && val !== "" && typeof val !== "object") {
      return String(val);
    }
    // Return empty or fallback placeholder
    return "";
  });
}

// HTML to plain text fallback converter
export function htmlToPlainText(html: string): string {
  if (!html) return "";
  return html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<br\s*[\/]?>/gi, "\n")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<\/div>/gi, "\n")
    .replace(/<\/h[1-6]>/gi, "\n\n")
    .replace(/<li>/gi, "• ")
    .replace(/<\/li>/gi, "\n")
    .replace(/<a\s+[^>]*href=["']([^"']*)["'][^>]*>(.*?)<\/a>/gi, "$2 ($1)")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

// Format relative date or ISO timestamp
export function formatDate(dateString?: string | null): string {
  if (!dateString) return "—";
  try {
    const d = new Date(dateString);
    if (isNaN(d.getTime())) return "—";
    return new Intl.DateTimeFormat("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "numeric",
      minute: "numeric",
    }).format(d);
  } catch {
    return "—";
  }
}

// Number formatter
export function formatNumber(num: number): string {
  return new Intl.NumberFormat("en-US").format(num);
}
