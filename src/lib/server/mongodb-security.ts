import { ObjectId } from "mongodb";
import { ApiError } from "./errors";

/**
 * Whitelist of permitted database collection names to prevent arbitrary collection access.
 */
export const ALLOWED_COLLECTIONS = new Set([
  "email_templates",
  "template_images",
  "campaigns",
  "contacts",
  "suppressionLists",
  "userCredentials",
  "users",
  "idempotencyKeys",
  "emailEvents",
  "campaignJobs",
  "rateLimits",
  "emailVerificationTokens",
  "passwordResetTokens",
  "domainVerifications",
]);

/**
 * Validates that a collection name is on the strict allowed list.
 */
export function assertAllowedCollection(collection: string): string {
  if (!ALLOWED_COLLECTIONS.has(collection)) {
    throw new ApiError(400, "Access to the requested resource collection is not permitted.", "INVALID_COLLECTION");
  }
  return collection;
}

/**
 * Validates whether an ID is a valid 24-character hexadecimal MongoDB ObjectId string.
 */
export function isValidObjectIdString(id: unknown): id is string {
  return typeof id === "string" && /^[0-9a-fA-F]{24}$/.test(id.trim());
}

/**
 * Safely parses and validates an ObjectId.
 * Throws an ApiError if the ID is not a valid 24-character hex string.
 */
export function parseObjectId(id: unknown, fieldName = "ID"): ObjectId {
  if (!isValidObjectIdString(id)) {
    throw new ApiError(400, `Invalid ${fieldName} format. Must be a 24-character hex ObjectId.`, "INVALID_ID");
  }
  return new ObjectId(id.trim());
}

/**
 * Recursively inspects and sanitizes user input objects to prevent NoSQL operator injection.
 * Strips any keys starting with "$" (MongoDB operators like $gt, $ne, $where, $regex)
 * and keys containing dot-notation ("profile.role", "user.isAdmin").
 */
export function sanitizeMongoInput<T>(input: T, depth = 0): T {
  if (depth > 10) {
    throw new ApiError(400, "Input payload nesting level exceeded.", "INVALID_INPUT");
  }
  if (input === null || typeof input !== "object") {
    return input;
  }

  if (Array.isArray(input)) {
    return input.map((item) => sanitizeMongoInput(item, depth + 1)) as unknown as T;
  }

  const clean: Record<string, unknown> = {};
  const keys = Object.getOwnPropertyNames(input);
  for (const key of keys) {
    // Block dangerous keys: MongoDB operators ($), dot notation (.), prototype pollution
    if (key.startsWith("$") || key.includes(".") || key === "__proto__" || key === "constructor" || key === "prototype") {
      throw new ApiError(400, `Disallowed query or update parameter: "${key}".`, "NOSQL_INJECTION_DETECTED");
    }

    clean[key] = sanitizeMongoInput((input as Record<string, unknown>)[key], depth + 1);
  }

  return clean as T;
}

/**
 * Constructs a safe ID lookup filter matching custom alphanumeric IDs and/or ObjectIds,
 * strictly scoped to the authenticated user.
 */
export function buildSafeOwnershipFilter(id: string, userId: string): Record<string, unknown> {
  // Enforce scalar string validation
  if (typeof id !== "string" || !id.trim()) {
    throw new ApiError(400, "Invalid identifier.", "INVALID_ID");
  }
  if (typeof userId !== "string" || !userId.trim()) {
    throw new ApiError(401, "Authentication required.", "UNAUTHORIZED");
  }

  const cleanId = id.trim();
  const cleanUserId = userId.trim();

  // If the id is a valid 24-char hex string, match either the _id ObjectId or string id
  if (isValidObjectIdString(cleanId)) {
    return {
      userId: cleanUserId,
      $or: [{ id: cleanId }, { _id: new ObjectId(cleanId) }],
    };
  }

  return {
    userId: cleanUserId,
    $or: [{ id: cleanId }, { _id: cleanId }],
  };
}

/**
 * Enforces safe, bounded pagination parameters to prevent Denial-of-Service.
 */
export function parseSafePagination(searchParams: URLSearchParams, defaultLimit = 20, maxLimit = 100) {
  const rawLimit = Number(searchParams.get("limit"));
  const limit = Math.min(Math.max(Number.isFinite(rawLimit) && rawLimit > 0 ? Math.floor(rawLimit) : defaultLimit, 1), maxLimit);
  const rawCursor = searchParams.get("cursor");
  const cursor = typeof rawCursor === "string" && rawCursor.trim().length > 0 && /^[a-zA-Z0-9_-]{1,128}$/.test(rawCursor.trim())
    ? rawCursor.trim()
    : null;

  return { limit, cursor };
}

/**
 * Escapes regex special characters to prevent Regular Expression Denial of Service (ReDoS).
 */
export function safeEscapeRegex(query: string, maxLen = 100): string {
  if (typeof query !== "string") return "";
  const truncated = query.slice(0, maxLen);
  return truncated.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&");
}

/**
 * Allowlist helper: extracts only explicitly permitted keys from an object,
 * preventing mass-assignment and privilege escalation attacks.
 */
export function allowlistFields<T extends Record<string, unknown>, K extends keyof T>(
  data: T,
  allowedKeys: readonly K[]
): Pick<T, K> {
  const result = {} as Pick<T, K>;
  for (const key of allowedKeys) {
    if (Object.prototype.hasOwnProperty.call(data, key) && data[key] !== undefined) {
      result[key] = data[key];
    }
  }
  return result;
}
