import { after, NextRequest } from "next/server";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { apiError, json, parseJson } from "@/lib/server/api";
import { sendCampaignSchema } from "@/lib/server/validation";
import { enqueueCampaign, processCampaign } from "@/lib/server/campaigns";
import { rateLimit } from "@/lib/server/rate-limit";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(req: NextRequest) {
  try {
    const user = await requireUser(req);
    const input = await parseJson(req, sendCampaignSchema, 900_000);
    await rateLimit(user.uid, "campaign-send", 10);
    const { campaign, replayed } = await enqueueCampaign(user, input);
    if (["queued", "sending"].includes(campaign.status)) {
      after(async () => {
        try { await processCampaign(campaign.id); }
        catch { console.error("Campaign processing deferred to worker", { campaignId: campaign.id }); }
      });
    }
    return json({ success: true, campaignId: campaign.id, campaign, status: campaign.status, stats: campaign.stats, replayed }, 202);
  } catch (error) { return apiError(error); }
}
