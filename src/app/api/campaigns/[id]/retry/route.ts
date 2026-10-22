import { after, NextRequest } from "next/server";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { apiError, json } from "@/lib/server/api";
import { idSchema } from "@/lib/server/validation";
import { processCampaign, retryCampaign } from "@/lib/server/campaigns";
import { resolveSmtp } from "@/lib/server/settings";
import { rateLimit } from "@/lib/server/rate-limit";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const user = await requireUser(req);
    const id = idSchema.parse((await params).id);
    await rateLimit(user.uid, "campaign-retry", 5);
    await resolveSmtp(user);
    const retriedTotal = await retryCampaign(user.uid, id);
    after(async () => {
      try { await processCampaign(id); }
      catch { console.error("Campaign retry deferred to worker", { campaignId: id }); }
    });
    return json({ success: true, campaignId: id, status: "queued", retriedTotal }, 202);
  } catch (error) { return apiError(error); }
}
