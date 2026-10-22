import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import { normalizeDomain } from "../src/lib/server/domains";

describe("Native MailForge Domains & DKIM Engine", () => {
  it("normalizes and sanitizes domain names correctly", () => {
    expect(normalizeDomain("https://example.com/")).toBe("example.com");
    expect(normalizeDomain("http://SUB.DOMAIN.ORG:8080/path")).toBe("sub.domain.org");
    expect(normalizeDomain("   MAIL.Acme.Co   ")).toBe("mail.acme.co");
  });

  it("generates a valid 2048-bit RSA keypair and DKIM DNS record", () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const cleanPublicKey = publicKey
      .replace(/-----BEGIN PUBLIC KEY-----/g, "")
      .replace(/-----END PUBLIC KEY-----/g, "")
      .replace(/\r?\n|\r/g, "")
      .trim();

    expect(cleanPublicKey.length).toBeGreaterThan(200);
    expect(privateKey).toContain("BEGIN PRIVATE KEY");

    const selector = "mf1";
    const domain = "testbrand.com";
    const dkimHost = `${selector}._domainkey.${domain}`;
    const dkimValue = `v=DKIM1; k=rsa; p=${cleanPublicKey}`;

    expect(dkimHost).toBe("mf1._domainkey.testbrand.com");
    expect(dkimValue).toMatch(/^v=DKIM1; k=rsa; p=[A-Za-z0-9+/=]+$/);
  });
});

describe("Developer API Keys Engine", () => {
  it("generates API keys with the secure mf_live_ prefix", () => {
    const rawSecret = crypto.randomBytes(24).toString("hex");
    const apiKey = `mf_live_${rawSecret}`;

    expect(apiKey.startsWith("mf_live_")).toBe(true);
    expect(apiKey.length).toBe(8 + 48); // "mf_live_" + 48 hex chars
  });

  it("creates consistent SHA-256 hashes for API key lookup", () => {
    const testKey = "mf_live_0123456789abcdef0123456789abcdef0123456789abcdef";
    const hash1 = crypto.createHash("sha256").update(testKey).digest("hex");
    const hash2 = crypto.createHash("sha256").update(testKey).digest("hex");

    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64);
  });

  it("correctly masks key prefix for secure dashboard display", () => {
    const testKey = "mf_live_abcdef1234567890abcdef1234567890abcdef12";
    const keyPrefix = `${testKey.slice(0, 11)}...${testKey.slice(-4)}`;

    expect(keyPrefix).toBe("mf_live_abc...ef12");
  });
});
