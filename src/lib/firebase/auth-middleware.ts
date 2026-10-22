import { NextRequest } from "next/server";
import { verifyFirebaseIdToken } from "./verify-token";
import { ApiError } from "@/lib/server/errors";

export interface AuthenticatedUser {
  uid: string;
  email: string;
  name?: string;
  picture?: string;
}

export async function requireUser(req: NextRequest): Promise<AuthenticatedUser> {
  const token =
    req.headers.get("authorization")?.match(/^Bearer\s+(\S+)$/i)?.[1] ||
    req.cookies.get("mf_auth_token")?.value;

  if (!token) {
    throw new ApiError(401, "Please sign in to perform this operation.", "UNAUTHORIZED");
  }

  let decoded;
  try {
    decoded = await verifyFirebaseIdToken(token);
  } catch (error: any) {
    const msg = error?.message || "";
    if (/expired/i.test(msg)) {
      throw new ApiError(401, "Your session has expired. Please sign in again.", "UNAUTHORIZED");
    }
    throw new ApiError(401, "Your session is invalid. Please sign in again.", "UNAUTHORIZED");
  }
  if (!decoded.email || !decoded.email_verified) {
    throw new ApiError(403, "A verified email address is required.", "EMAIL_NOT_VERIFIED");
  }
  const email = decoded.email.toLowerCase();
  const allowed = process.env.MAILFORGE_ALLOWED_EMAILS?.split(",").map((value) => value.trim().toLowerCase()).filter(Boolean);
  if (allowed?.length && !allowed.includes(email)) throw new ApiError(403, "This account does not have access to this workspace.", "FORBIDDEN");
  return { uid: decoded.uid, email, name: decoded.name, picture: decoded.picture };
}
