import { NextRequest } from "next/server";
import { getMongoDb } from "@/lib/mongodb";
import { apiError, json } from "@/lib/server/api";
import { authenticateApiKey } from "@/lib/server/api-keys";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { ApiError } from "@/lib/server/errors";

async function resolveCaller(req: NextRequest): Promise<{ uid: string; email: string }> {
  const authHeader = req.headers.get("authorization") || req.headers.get("x-api-key");
  if (authHeader && (authHeader.startsWith("Bearer mf_live_") || authHeader.startsWith("mf_live_"))) {
    return authenticateApiKey(authHeader);
  }

  try {
    const user = await requireUser(req);
    return { uid: user.uid, email: user.email };
  } catch {
    throw new ApiError(401, "Missing or invalid API key.", "UNAUTHORIZED");
  }
}

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const caller = await resolveCaller(req);
    const { id } = await params;
    const db = await getMongoDb();

    const email: any = await db.collection("apiDispatches").findOne({
      id,
      userId: caller.uid,
    });

    if (!email) {
      throw new ApiError(404, "Email not found.", "NOT_FOUND");
    }

    return json({
      id: email.id,
      from: email.from,
      to: email.to,
      subject: email.subject,
      status: email.status,
      created_at: email.createdAt,
      error: email.error || null,
      provider_message_id: email.providerMessageId || null,
    });
  } catch (error) {
    return apiError(error);
  }
}
