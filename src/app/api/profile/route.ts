import { NextRequest } from "next/server";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { apiError, json } from "@/lib/server/api";
import { getUserProfile } from "@/lib/server/settings";

export async function GET(req: NextRequest) {
  try { return json({ profile: await getUserProfile(await requireUser(req)) }); }
  catch (error) { return apiError(error); }
}
