import { NextRequest, NextResponse } from "next/server";
import { adminAuth, isFirebaseAdminConfigured } from "./admin";

export interface AuthenticatedUser {
  uid: string;
  email: string;
  name?: string;
  picture?: string;
}

export async function verifyServerAuth(req: NextRequest): Promise<AuthenticatedUser | null> {
  const authHeader = req.headers.get("authorization");
  let token: string | null = null;

  if (authHeader && authHeader.startsWith("Bearer ")) {
    token = authHeader.substring(7).trim();
  } else {
    // Check cookie fallback
    token = req.cookies.get("mf_auth_token")?.value || null;
  }

  if (!token) {
    return null;
  }

  // Real Firebase Admin verification
  if (adminAuth && isFirebaseAdminConfigured) {
    try {
      const decoded = await adminAuth.verifyIdToken(token);
      return {
        uid: decoded.uid,
        email: decoded.email || "",
        name: decoded.name || undefined,
        picture: decoded.picture || undefined,
      };
    } catch (err) {
      console.error("Token verification failed:", err);
      return null;
    }
  }

  // If Admin is not yet configured with real service account key, decode the payload safely for dev
  try {
    const parts = token.split(".");
    if (parts.length === 3) {
      const payload = JSON.parse(Buffer.from(parts[1], "base64").toString("utf-8"));
      if (payload.user_id || payload.sub) {
        return {
          uid: payload.user_id || payload.sub,
          email: payload.email || "",
          name: payload.name || undefined,
          picture: payload.picture || undefined,
        };
      }
    }
  } catch (e) {
    console.warn("Fallback token decode error:", e);
  }

  return null;
}

export function unauthorizedResponse(message = "Unauthorized: Please sign in to perform this operation") {
  return NextResponse.json({ error: message, code: "UNAUTHORIZED" }, { status: 401 });
}
