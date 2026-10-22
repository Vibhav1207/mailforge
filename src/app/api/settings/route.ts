import { NextRequest } from "next/server";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { apiError, json, parseJson } from "@/lib/server/api";
import { settingsSchema } from "@/lib/server/validation";
import { saveUserSettings } from "@/lib/server/settings";
import { rateLimit } from "@/lib/server/rate-limit";

export async function PATCH(req: NextRequest) {
  try {
    const user = await requireUser(req);
    const input = await parseJson(req, settingsSchema, 32_000);
    await rateLimit(user.uid, "settings", 30);
    return json({ settings: await saveUserSettings(user, input) });
  } catch (error) { return apiError(error); }
}
