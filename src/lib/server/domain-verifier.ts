import dns from "node:dns/promises";
import { getMongoDb } from "@/lib/mongodb";

export interface DomainDnsCheckResult {
  domain: string;
  hasSpf: boolean;
  spfRecord?: string;
  hasDmarc: boolean;
  dmarcRecord?: string;
  hasMx: boolean;
  mxRecords?: string[];
  status: "verified" | "pending" | "misconfigured";
  checkedAt: string;
}

/**
 * Checks the live DNS records of a domain to verify SPF, DMARC, and MX configuration.
 */
export async function checkDomainDns(domain: string): Promise<DomainDnsCheckResult> {
  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  const resolver = new dns.Resolver();
  try {
    resolver.setServers(["8.8.8.8", "1.1.1.1"]);
  } catch {}

  let hasSpf = false;
  let spfRecord: string | undefined;
  let hasDmarc = false;
  let dmarcRecord: string | undefined;
  let hasMx = false;
  let mxRecords: string[] = [];

  // Check SPF
  try {
    const txtRecords = await resolver.resolveTxt(cleanDomain);
    for (const record of txtRecords) {
      const full = record.join("");
      if (full.startsWith("v=spf1")) {
        hasSpf = true;
        spfRecord = full;
        break;
      }
    }
  } catch {}

  // Check DMARC
  try {
    const dmarcTxt = await resolver.resolveTxt(`_dmarc.${cleanDomain}`);
    for (const record of dmarcTxt) {
      const full = record.join("");
      if (full.startsWith("v=DMARC1")) {
        hasDmarc = true;
        dmarcRecord = full;
        break;
      }
    }
  } catch {}

  // Check MX
  try {
    const mx = await resolver.resolveMx(cleanDomain);
    if (mx && mx.length > 0) {
      hasMx = true;
      mxRecords = mx.map((m) => `${m.exchange} (priority ${m.priority})`);
    }
  } catch {}

  const status: "verified" | "pending" | "misconfigured" =
    hasSpf && hasDmarc ? "verified" : hasSpf || hasMx ? "pending" : "misconfigured";

  const result: DomainDnsCheckResult = {
    domain: cleanDomain,
    hasSpf,
    spfRecord,
    hasDmarc,
    dmarcRecord,
    hasMx,
    mxRecords,
    status,
    checkedAt: new Date().toISOString(),
  };

  // Cache in MongoDB
  try {
    const db = await getMongoDb();
    await db.collection("domainVerifications").updateOne(
      { domain: cleanDomain },
      { $set: result },
      { upsert: true }
    );
  } catch (err) {
    console.warn("Could not cache domain verification in MongoDB:", (err as Error)?.message);
  }

  return result;
}

/**
 * Validates that an outgoing email address belongs to a verified domain,
 * preventing arbitrary unverified sender spoofing in production.
 */
export async function assertVerifiedSenderDomain(fromEmail: string): Promise<boolean> {
  const parts = fromEmail.trim().toLowerCase().split("@");
  if (parts.length !== 2) return false;
  const domain = parts[1];

  // If using Gmail SMTP or development mode, allow standard addresses
  if (domain === "gmail.com" || domain === "googlemail.com" || process.env.NODE_ENV !== "production") {
    return true;
  }

  // Check MailForge native registered and verified domains
  try {
    const db = await getMongoDb();
    const verifiedDoc = await db.collection("domains").findOne({ domain, status: "verified" });
    if (verifiedDoc) return true;
  } catch (err) {
    console.warn("Could not query verified domains:", (err as Error)?.message);
  }

  // Fallback to live DNS check (SPF must exist)
  try {
    const check = await checkDomainDns(domain);
    return check.hasSpf;
  } catch {
    return false;
  }
}
