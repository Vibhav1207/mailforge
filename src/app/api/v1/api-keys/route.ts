import { NextRequest } from "next/server";
import { z } from "zod";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { apiError, json, parseJson } from "@/lib/server/api";
import { createApiKey, listApiKeys } from "@/lib/server/api-keys";
import { rateLimit } from "@/lib/server/rate-limit";

export async function GET(req: NextRequest) {
  try {
    const user = await requireUser(req);
    await rateLimit(user.uid, "api-keys-list", 30);

    const keys = await listApiKeys(user);
    return json({ keys });
  } catch (error) {
    return apiError(error);
  }
}

export async function POST(req: NextRequest) {
  try {
    const user = await requireUser(req);
    await rateLimit(user.uid, "api-keys-create", 10);

    const input = await parseJson(
      req,
      z.object({
        name: z.string().trim().min(1).max(64),
      })
    );

    const created = await createApiKey(user, input.name);
    return json({ success: true, key: created }, 201);
  } catch (error) {
    return apiError(error);
  }
}
