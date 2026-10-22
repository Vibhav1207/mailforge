import { describe, it, expect } from "vitest";
import {
  sanitizeMongoInput,
  isValidObjectIdString,
  parseObjectId,
  buildSafeOwnershipFilter,
  assertAllowedCollection,
  parseSafePagination,
  safeEscapeRegex,
  allowlistFields,
} from "../src/lib/server/mongodb-security";
import { generateSecureToken, hashToken } from "../src/lib/server/tokens";
import { hashPassword } from "../src/app/api/auth/reset-password/route";

describe("MongoDB & NoSQL Injection Protection", () => {
  it("rejects MongoDB operator injection like $ne, $gt, $where, $regex", () => {
    expect(() => sanitizeMongoInput({ email: { $ne: null } })).toThrow("Disallowed query or update parameter");
    expect(() => sanitizeMongoInput({ age: { $gt: 0 } })).toThrow("Disallowed query or update parameter");
    expect(() => sanitizeMongoInput({ $where: "sleep(5000)" })).toThrow("Disallowed query or update parameter");
    expect(() => sanitizeMongoInput({ username: { $regex: ".*" } })).toThrow("Disallowed query or update parameter");
    expect(() => sanitizeMongoInput({ role: { $in: ["admin", "superadmin"] } })).toThrow("Disallowed query or update parameter");
  });

  it("rejects dot-notation injection attacks like profile.role or user.isAdmin", () => {
    expect(() => sanitizeMongoInput({ "profile.role": "admin" })).toThrow("Disallowed query or update parameter");
    expect(() => sanitizeMongoInput({ "user.isAdmin": true })).toThrow("Disallowed query or update parameter");
    expect(() => sanitizeMongoInput({ "settings.permissions.admin": true })).toThrow("Disallowed query or update parameter");
  });

  it("rejects prototype pollution attempts", () => {
    expect(() => sanitizeMongoInput(JSON.parse('{"__proto__": {"admin": true}}'))).toThrow();
    expect(() => sanitizeMongoInput(JSON.parse('{"constructor": {"prototype": {"admin": true}}}'))).toThrow();
  });

  it("allows clean scalar fields and nested safe objects", () => {
    const safeData = {
      name: "Newsletter Template",
      subject: "Welcome to MailForge",
      tags: ["marketing", "welcome"],
      metadata: {
        theme: "dark",
        version: 2,
      },
    };
    expect(sanitizeMongoInput(safeData)).toEqual(safeData);
  });
});

describe("ObjectId Validation Security", () => {
  it("validates authentic 24-character hex ObjectIds", () => {
    expect(isValidObjectIdString("507f1f77bcf86cd799439011")).toBe(true);
    expect(isValidObjectIdString("64a7c1b5e4b0a1c2d3e4f5a6")).toBe(true);
  });

  it("rejects malicious or invalid ObjectIds", () => {
    expect(isValidObjectIdString("not-an-object-id")).toBe(false);
    expect(isValidObjectIdString("507f1f77bcf86cd79943901")).toBe(false); // 23 chars
    expect(isValidObjectIdString("507f1f77bcf86cd7994390111")).toBe(false); // 25 chars
    expect(isValidObjectIdString({ $gt: "" } as any)).toBe(false);
    expect(isValidObjectIdString(123456789012 as any)).toBe(false);
  });

  it("parseObjectId throws ApiError on invalid input", () => {
    expect(() => parseObjectId("invalid_id")).toThrow("Invalid ID format");
    expect(() => parseObjectId(null as any)).toThrow("Invalid ID format");
  });
});

describe("IDOR & Ownership Filter Security", () => {
  it("strictly scopes database filters to the authenticated userId", () => {
    const filter = buildSafeOwnershipFilter("tpl_12345", "user_abc987");
    expect(filter.userId).toBe("user_abc987");
    expect(filter.$or).toBeDefined();
  });

  it("rejects empty or non-string IDs to prevent wildcard queries", () => {
    expect(() => buildSafeOwnershipFilter("", "user_abc987")).toThrow();
    expect(() => buildSafeOwnershipFilter("   ", "user_abc987")).toThrow();
    expect(() => buildSafeOwnershipFilter(null as any, "user_abc987")).toThrow();
  });
});

describe("Collection Allowlisting Security", () => {
  it("permits allowed application collections", () => {
    expect(assertAllowedCollection("email_templates")).toBe("email_templates");
    expect(assertAllowedCollection("campaigns")).toBe("campaigns");
    expect(assertAllowedCollection("contacts")).toBe("contacts");
    expect(assertAllowedCollection("users")).toBe("users");
  });

  it("rejects unauthorized or arbitrary collection access", () => {
    expect(() => assertAllowedCollection("system.users")).toThrow("Access to the requested resource collection is not permitted");
    expect(() => assertAllowedCollection("arbitrary_collection")).toThrow();
    expect(() => assertAllowedCollection("../admin")).toThrow();
  });
});

describe("Safe Pagination Security", () => {
  it("enforces maximum query limit bounds to prevent DoS", () => {
    const params = new URLSearchParams("limit=9999999");
    const { limit } = parseSafePagination(params, 20, 100);
    expect(limit).toBe(100);
  });

  it("clamps negative or zero limits to safe minimums", () => {
    const paramsNegative = new URLSearchParams("limit=-50");
    expect(parseSafePagination(paramsNegative).limit).toBe(20);

    const paramsZero = new URLSearchParams("limit=0");
    expect(parseSafePagination(paramsZero).limit).toBe(20);
  });

  it("validates cursors against allowed character set", () => {
    const validParams = new URLSearchParams("cursor=rec_123456");
    expect(parseSafePagination(validParams).cursor).toBe("rec_123456");

    const maliciousParams = new URLSearchParams("cursor={\"$gt\":\"\"}");
    expect(parseSafePagination(maliciousParams).cursor).toBeNull();
  });
});

describe("Search & Regex ReDoS Security", () => {
  it("escapes regex meta-characters", () => {
    const input = "test.*+?^${}()|[]\\";
    const escaped = safeEscapeRegex(input);
    expect(escaped).not.toContain(".*");
    expect(() => new RegExp(escaped)).not.toThrow();
  });

  it("truncates excessively long search inputs", () => {
    const longString = "a".repeat(500);
    expect(safeEscapeRegex(longString, 50).length).toBe(50);
  });
});

describe("Field Allowlisting Security", () => {
  it("strips unauthorized and privileged fields", () => {
    const untrustedPayload = {
      name: "Safe Name",
      role: "admin",
      isAdmin: true,
      permissions: ["all"],
      emailVerified: true,
    };

    const allowed = allowlistFields(untrustedPayload, ["name"] as const);
    expect(allowed).toEqual({ name: "Safe Name" });
    expect((allowed as any).role).toBeUndefined();
    expect((allowed as any).isAdmin).toBeUndefined();
  });
});

describe("Cryptographic Token & Password Hashing Security", () => {
  it("generates 256-bit high-entropy random tokens", () => {
    const token1 = generateSecureToken(32);
    const token2 = generateSecureToken(32);
    expect(token1.length).toBe(64);
    expect(token2.length).toBe(64);
    expect(token1).not.toBe(token2);
  });

  it("produces deterministic SHA-256 token hashes for database lookup", () => {
    const token = "abcdef1234567890abcdef1234567890";
    const hash1 = hashToken(token);
    const hash2 = hashToken(token);
    expect(hash1).toBe(hash2);
    expect(hash1).not.toBe(token);
  });

  it("hashes passwords securely using scrypt with random salt", () => {
    const pass = "StrongP@ssw0rd!2026";
    const hash1 = hashPassword(pass);
    const hash2 = hashPassword(pass);
    expect(hash1).toContain(":");
    expect(hash1).not.toBe(hash2); // Different salts
  });
});
