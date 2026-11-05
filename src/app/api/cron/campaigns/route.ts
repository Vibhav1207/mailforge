import { NextRequest } from "next/server";
import { apiError, json } from "@/lib/server/api";
import { requireCron } from "@/lib/server/cron-auth";
import { runCampaignWorker } from "@/lib/server/campaign-worker";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function GET(req: NextRequest) {
  try {
    requireCron(req);
    const { processed, failed } = await runCampaignWorker();
    return json({ success: failed === 0, processed, failed }, failed ? 503 : 200);
  } catch (error) { return apiError(error); }
}
