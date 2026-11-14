import { NextRequest } from "next/server";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { apiError, json, parseJson } from "@/lib/server/api";
import { sendCampaignSchema } from "@/lib/server/validation";
import { enqueueCampaign, processCampaign } from "@/lib/server/campaigns";
import { getOwned } from "@/lib/server/data";
import { rateLimit } from "@/lib/server/rate-limit";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(req: NextRequest) {
  try {
    const user = await requireUser(req);
    const input = await parseJson(req, sendCampaignSchema, 5_000_000);
    await rateLimit(user.uid, "campaign-send", 20);
    const { campaign, replayed } = await enqueueCampaign(user, input);
    let finished = false;

    // Execute first processing batch within active HTTP request so serverless doesn't terminate early
    if (["queued", "sending"].includes(campaign.status) && !input.scheduledFor) {
      try {
        const result = await processCampaign(campaign.id, 15_000);
        finished = result?.finished ?? false;
      } catch (err) {
        console.warn("Initial send batch warning:", err);
      }
    }

    const updated = await getOwned("campaigns", campaign.id, user.uid).catch(() => null);
    const current = (updated as any) || campaign;

    return json({
      success: true,
      campaignId: campaign.id,
      campaign: current,
      finished,
      status: current.status,
      stats: current.stats,
      replayed
    }, 200);
  } catch (error) { return apiError(error); }
}
