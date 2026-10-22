import { NextRequest } from "next/server";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { apiError, json } from "@/lib/server/api";
import { revokeApiKey } from "@/lib/server/api-keys";
import { rateLimit } from "@/lib/server/rate-limit";

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const user = await requireUser(req);
    const { id } = await params;
    await rateLimit(user.uid, "api-keys-revoke", 15);

    const revoked = await revokeApiKey(user, id);
    return json({ success: revoked });
  } catch (error) {
    return apiError(error);
  }
}
