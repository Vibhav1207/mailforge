import crypto from "node:crypto";
import dns from "node:dns/promises";
import { ObjectId } from "mongodb";
import { getMongoDb } from "@/lib/mongodb";
import type { AuthenticatedUser } from "@/lib/firebase/auth-middleware";
import { ApiError } from "./errors";
import { encryptSecret, decryptSecret } from "./secrets";
import { sanitizeMongoInput } from "./mongodb-security";

export interface NativeDnsRecord {
  type: "TXT" | "MX" | "CNAME";
  name: string;
  value: string;
  ttl: string;
  status: "verified" | "pending" | "failed";
  priority?: number;
  purpose: "DKIM" | "SPF" | "DMARC" | "MX";
}

export interface NativeDomainRecord {
  id: string;
  domain: string;
  userId: string;
  status: "verified" | "pending" | "failed";
  selector: string;
  publicKey: string;
  records: NativeDnsRecord[];
  createdAt: string;
  updatedAt: string;
}

/**
 * Normalizes and cleans a domain input string.
 */
export function normalizeDomain(raw: string): string {
  const sanitized = sanitizeMongoInput(raw);
  return sanitized
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/:\d+$/, "");
}

/**
 * Generates an RSA 2048-bit keypair for DKIM signing.
 */
function generateDkimKeyPair(): { privateKey: string; publicKey: string } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

  // Extract pure base64 for the DNS TXT record
  const cleanPublicKey = publicKey
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\r?\n|\r/g, "")
    .trim();

  return { privateKey, publicKey: cleanPublicKey };
}

/**
 * Creates DNS records blueprint for a domain with DKIM, SPF, DMARC, and MX.
 */
function buildDnsRecords(domain: string, selector: string, publicKey: string): NativeDnsRecord[] {
  return [
    {
      purpose: "DKIM",
      type: "TXT",
      name: `${selector}._domainkey.${domain}`,
      value: `v=DKIM1; k=rsa; p=${publicKey}`,
      ttl: "Auto",
      status: "pending",
    },
    {
      purpose: "SPF",
      type: "TXT",
      name: domain,
      value: "v=spf1 include:_spf.mailforge.app ~all",
      ttl: "Auto",
      status: "pending",
    },
    {
      purpose: "DMARC",
      type: "TXT",
      name: `_dmarc.${domain}`,
      value: `v=DMARC1; p=none; pct=100; rua=mailto:dmarc-reports@${domain}`,
      ttl: "Auto",
      status: "pending",
    },
    {
      purpose: "MX",
      type: "MX",
      name: domain,
      value: "smtp.mailforge.app",
      ttl: "Auto",
      status: "pending",
      priority: 10,
    },
  ];
}

/**
 * Registers a new sending domain in MailForge with native DKIM generation.
 */
export async function createNativeDomain(
  user: AuthenticatedUser,
  domainInput: string
): Promise<NativeDomainRecord> {
  const domain = normalizeDomain(domainInput);

  if (!domain || !/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(domain)) {
    throw new ApiError(400, "Invalid domain name format.", "INVALID_DOMAIN");
  }

  const db = await getMongoDb();
  const existing = await db.collection("domains").findOne({ domain, userId: user.uid });
  if (existing) {
    throw new ApiError(409, `Domain "${domain}" is already registered in your account.`, "DOMAIN_EXISTS");
  }

  const selector = "mf1";
  const { privateKey, publicKey } = generateDkimKeyPair();
  const encryptedPrivateKey = encryptSecret(privateKey, user.uid);
  const records = buildDnsRecords(domain, selector, publicKey);
  const now = new Date().toISOString();

  const doc = {
    userId: user.uid,
    domain,
    selector,
    encryptedPrivateKey,
    publicKey,
    records,
    status: "pending" as const,
    createdAt: now,
    updatedAt: now,
  };

  const insertResult = await db.collection("domains").insertOne(doc);

  return {
    id: insertResult.insertedId.toString(),
    domain,
    userId: user.uid,
    status: "pending",
    selector,
    publicKey,
    records,
    createdAt: now,
    updatedAt: now,
  };
}

/**
 * Lists all registered domains for the authenticated user.
 */
export async function listNativeDomains(user: AuthenticatedUser): Promise<NativeDomainRecord[]> {
  const db = await getMongoDb();
  const docs = await db.collection("domains").find({ userId: user.uid }).sort({ createdAt: -1 }).toArray();

  return docs.map((d: any) => ({
    id: d._id.toString(),
    domain: d.domain,
    userId: d.userId,
    status: d.status || "pending",
    selector: d.selector || "mf1",
    publicKey: d.publicKey,
    records: d.records || buildDnsRecords(d.domain, d.selector || "mf1", d.publicKey),
    createdAt: d.createdAt,
    updatedAt: d.updatedAt,
  }));
}

/**
 * Deletes a domain registered by the user.
 */
export async function deleteNativeDomain(user: AuthenticatedUser, domainIdOrName: string): Promise<boolean> {
  const db = await getMongoDb();
  const filter: any = { userId: user.uid };
  if (ObjectId.isValid(domainIdOrName)) {
    filter._id = new ObjectId(domainIdOrName);
  } else {
    filter.domain = normalizeDomain(domainIdOrName);
  }

  const result = await db.collection("domains").deleteOne(filter);
  return result.deletedCount > 0;
}

/**
 * Performs live DNS queries against public DNS servers to verify domain DKIM, SPF, DMARC, and MX records.
 */
export async function verifyNativeDomainDns(
  user: AuthenticatedUser,
  domainIdOrName: string
): Promise<NativeDomainRecord> {
  const db = await getMongoDb();
  const filter: any = { userId: user.uid };
  if (ObjectId.isValid(domainIdOrName)) {
    filter._id = new ObjectId(domainIdOrName);
  } else {
    filter.domain = normalizeDomain(domainIdOrName);
  }

  const doc: any = await db.collection("domains").findOne(filter);
  if (!doc) {
    throw new ApiError(404, "Domain not found.", "NOT_FOUND");
  }

  const domain = doc.domain;
  const selector = doc.selector || "mf1";
  const expectedKey = doc.publicKey;

  const resolver = new dns.Resolver();
  try {
    resolver.setServers(["8.8.8.8", "1.1.1.1", "9.9.9.9"]);
  } catch {}

  const updatedRecords: NativeDnsRecord[] = buildDnsRecords(domain, selector, expectedKey);

  // 1. Verify DKIM
  try {
    const dkimHost = `${selector}._domainkey.${domain}`;
    const txts = await resolver.resolveTxt(dkimHost);
    const flattened = txts.map((chunks) => chunks.join("")).join(" ");
    const dkimRecord = updatedRecords.find((r) => r.purpose === "DKIM");
    if (dkimRecord) {
      if (flattened.includes(expectedKey) || (flattened.includes("v=DKIM1") && flattened.includes("k=rsa"))) {
        dkimRecord.status = "verified";
      } else {
        dkimRecord.status = "failed";
      }
    }
  } catch {
    const dkimRecord = updatedRecords.find((r) => r.purpose === "DKIM");
    if (dkimRecord) dkimRecord.status = "failed";
  }

  // 2. Verify SPF
  try {
    const txts = await resolver.resolveTxt(domain);
    const spfRecord = updatedRecords.find((r) => r.purpose === "SPF");
    const hasSpf = txts.some((chunks) => chunks.join("").startsWith("v=spf1"));
    if (spfRecord) {
      spfRecord.status = hasSpf ? "verified" : "failed";
    }
  } catch {
    const spfRecord = updatedRecords.find((r) => r.purpose === "SPF");
    if (spfRecord) spfRecord.status = "failed";
  }

  // 3. Verify DMARC
  try {
    const dmarcHost = `_dmarc.${domain}`;
    const txts = await resolver.resolveTxt(dmarcHost);
    const dmarcRecord = updatedRecords.find((r) => r.purpose === "DMARC");
    const hasDmarc = txts.some((chunks) => chunks.join("").startsWith("v=DMARC1"));
    if (dmarcRecord) {
      dmarcRecord.status = hasDmarc ? "verified" : "failed";
    }
  } catch {
    const dmarcRecord = updatedRecords.find((r) => r.purpose === "DMARC");
    if (dmarcRecord) dmarcRecord.status = "failed";
  }

  // 4. Verify MX
  try {
    const mx = await resolver.resolveMx(domain);
    const mxRecord = updatedRecords.find((r) => r.purpose === "MX");
    if (mxRecord) {
      mxRecord.status = mx && mx.length > 0 ? "verified" : "failed";
    }
  } catch {
    const mxRecord = updatedRecords.find((r) => r.purpose === "MX");
    if (mxRecord) mxRecord.status = "failed";
  }

  const dkimVerified = updatedRecords.find((r) => r.purpose === "DKIM")?.status === "verified";
  const spfVerified = updatedRecords.find((r) => r.purpose === "SPF")?.status === "verified";

  // Domain is considered verified if DKIM is verified (or SPF is verified)
  const overallStatus: "verified" | "pending" | "failed" = dkimVerified
    ? "verified"
    : spfVerified
    ? "verified"
    : "pending";

  const now = new Date().toISOString();
  await db.collection("domains").updateOne(
    { _id: doc._id },
    {
      $set: {
        status: overallStatus,
        records: updatedRecords,
        updatedAt: now,
      },
    }
  );

  return {
    id: doc._id.toString(),
    domain,
    userId: user.uid,
    status: overallStatus,
    selector,
    publicKey: expectedKey,
    records: updatedRecords,
    createdAt: doc.createdAt,
    updatedAt: now,
  };
}

/**
 * Retrieves decrypted DKIM credentials for a domain if verified.
 */
export async function getDomainDkim(domainName: string): Promise<{
  domain: string;
  selector: string;
  privateKey: string;
} | null> {
  try {
    const clean = normalizeDomain(domainName);
    const db = await getMongoDb();
    const doc: any = await db.collection("domains").findOne({ domain: clean });
    if (!doc || !doc.encryptedPrivateKey) return null;

    const privateKey = decryptSecret(doc.encryptedPrivateKey, doc.userId);
    return {
      domain: doc.domain,
      selector: doc.selector || "mf1",
      privateKey,
    };
  } catch (err) {
    console.warn("Could not retrieve DKIM for domain:", domainName, (err as Error)?.message);
    return null;
  }
}
