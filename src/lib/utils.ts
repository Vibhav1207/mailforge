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

// Template variable interpolation {{name}}, {{firstName}}, {{company}}, {{email}}, custom fields, etc.
export function interpolateVariables(
  content: string,
  variables: Record<string, any>
): string {
  if (!content || !variables) return content || "";

  const norm = (s: string) => String(s || "").toLowerCase().replace(/[\s_\-]+/g, "");

  // Build a flat lookup map with normalized keys
  const lookup = new Map<string, any>();

  // Add custom fields first
  if (variables.customFields && typeof variables.customFields === "object") {
    for (const [k, v] of Object.entries(variables.customFields)) {
      if (v !== undefined && v !== null) {
        lookup.set(norm(k), v);
        lookup.set(k.toLowerCase(), v);
      }
    }
  }

  // Add top-level variables (higher priority)
  for (const [k, v] of Object.entries(variables)) {
    if (k !== "customFields" && v !== undefined && v !== null && typeof v !== "object") {
      lookup.set(norm(k), v);
      lookup.set(k.toLowerCase(), v);
    }
  }

  // Extract name derivatives
  const explicitName = variables.name || lookup.get("name") || lookup.get("fullname");
  const firstName = variables.firstName || lookup.get("firstname") || (explicitName ? String(explicitName).trim().split(/\s+/)[0] : "");
  const lastName = variables.lastName || lookup.get("lastname") || (explicitName && String(explicitName).trim().split(/\s+/).length > 1 ? String(explicitName).trim().split(/\s+/).slice(1).join(" ") : "");
  const fullName = explicitName || [firstName, lastName].filter(Boolean).join(" ") || variables.email?.split("@")[0] || "";

  return content.replace(/\{\{\s*([^{}]+?)\s*\}\}/g, (match, rawKey) => {
    const key = rawKey.trim();
    const keyNorm = norm(key);

    // Check direct / normalized match in lookup
    if (lookup.has(keyNorm)) {
      const val = lookup.get(keyNorm);
      if (val !== undefined && val !== null && typeof val !== "object") {
        return String(val);
      }
    }

    // Special derivative matching
    if (keyNorm === "name" || keyNorm === "fullname" || keyNorm === "displayname") {
      return fullName || "";
    }
    if (keyNorm === "firstname" || keyNorm === "fname") {
      return firstName || fullName || "";
    }
    if (keyNorm === "lastname" || keyNorm === "lname") {
      return lastName || "";
    }
    if (keyNorm === "email" || keyNorm === "emailaddress") {
      return variables.email || lookup.get("email") || "";
    }
    if (keyNorm === "company" || keyNorm === "companyname" || keyNorm === "organization") {
      return variables.company || lookup.get("company") || lookup.get("companyname") || "";
    }

    // Direct key in variables or customFields
    if (variables[key] !== undefined && typeof variables[key] !== "object") {
      return String(variables[key]);
    }
    if (variables.customFields && variables.customFields[key] !== undefined && typeof variables.customFields[key] !== "object") {
      return String(variables.customFields[key]);
    }

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
