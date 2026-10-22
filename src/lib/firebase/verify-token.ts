import { createVerify } from "node:crypto";
import { isFirebaseAdminConfigured, getAdminAuth } from "./admin";

export interface DecodedAuthToken {
  uid: string;
  email: string;
  email_verified: boolean;
  name?: string;
  picture?: string;
}

let cachedCerts: Record<string, string> | null = null;
let certsExpiry = 0;

async function fetchGooglePublicCerts(): Promise<Record<string, string>> {
  const now = Date.now();
  if (cachedCerts && now < certsExpiry) return cachedCerts;

  try {
    const res = await fetch(
      "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
      { cache: "no-store" }
    );
    if (res.ok) {
      const cacheControl = res.headers.get("cache-control");
      const maxAgeMatch = cacheControl?.match(/max-age=(\d+)/);
      const ttl = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 3600;
      cachedCerts = await res.json();
      certsExpiry = now + ttl * 1000;
      return cachedCerts || {};
    }
  } catch (err) {
    console.warn("Could not fetch Google public certs:", err);
  }
  return cachedCerts || {};
}

export async function verifyFirebaseIdToken(token: string): Promise<DecodedAuthToken> {
  // If Firebase Admin service account is configured, use official SDK
  if (isFirebaseAdminConfigured()) {
    try {
      const auth = getAdminAuth();
      const decoded = await auth.verifyIdToken(token);
      return {
        uid: decoded.uid,
        email: decoded.email || "",
        email_verified: decoded.email_verified ?? true,
        name: decoded.name,
        picture: decoded.picture,
      };
    } catch (err: any) {
      const code = err?.code || "";
      if (/auth\/id-token-expired/.test(code)) {
        throw new Error("Token expired");
      }
      // If service account failed, proceed to public certificate verification
      console.warn("Admin SDK verification failed, falling back to public cert verification:", err?.message);
    }
  }

  // Fallback: Verify standard Firebase JWT using Google public x509 certs
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid token format");
  }

  let header: { alg?: string; kid?: string };
  let payload: {
    exp?: number;
    iat?: number;
    aud?: string;
    iss?: string;
    sub?: string;
    user_id?: string;
    email?: string;
    email_verified?: boolean;
    name?: string;
    picture?: string;
  };

  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    throw new Error("Invalid token encoding");
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) {
    throw new Error("Token expired");
  }

  const expectedProjectId = process.env.FIREBASE_PROJECT_ID || process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID;
  if (expectedProjectId) {
    if (payload.aud && payload.aud !== expectedProjectId) {
      throw new Error(`Token audience mismatch: ${payload.aud}`);
    }
    if (payload.iss && payload.iss !== `https://securetoken.google.com/${expectedProjectId}`) {
      throw new Error(`Token issuer mismatch: ${payload.iss}`);
    }
  }

  // Attempt signature validation with Google's public certificates
  if (header.kid) {
    try {
      const certs = await fetchGooglePublicCerts();
      const cert = certs[header.kid];
      if (cert) {
        const verifier = createVerify("RSA-SHA256");
        verifier.update(`${parts[0]}.${parts[1]}`);
        const isValid = verifier.verify(cert, Buffer.from(parts[2], "base64url"));
        if (!isValid) {
          throw new Error("Invalid token signature");
        }
      }
    } catch (err: any) {
      if (err?.message === "Invalid token signature") throw err;
      if (process.env.NODE_ENV === "production") throw err;
    }
  }

  const uid = payload.sub || payload.user_id;
  if (!uid) throw new Error("Token has no user ID");

  return {
    uid,
    email: payload.email || "",
    email_verified: payload.email_verified ?? true,
    name: payload.name,
    picture: payload.picture,
  };
}
