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
    const input = await parseJson(req, sendCampaignSchema, 5_000_000);
    await rateLimit(user.uid, "campaign-send", 20);
    const { campaign, replayed } = await enqueueCampaign(user, input);
    if (["queued", "sending"].includes(campaign.status)) {
      let scheduled = false;
      try {
        if (typeof after === "function") {
          after(async () => {
            try { await processCampaign(campaign.id); }
            catch (err) { console.error("Campaign processing deferred to worker", { campaignId: campaign.id, error: err }); }
          });
          scheduled = true;
        }
      } catch {
        scheduled = false;
      }
      if (!scheduled) {
        processCampaign(campaign.id).catch((err) => console.error("Direct process error:", err));
      }
    }
    return json({ success: true, campaignId: campaign.id, campaign, status: campaign.status, stats: campaign.stats, replayed }, 202);
  } catch (error) { return apiError(error); }
}
