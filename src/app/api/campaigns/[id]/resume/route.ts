import { after, NextRequest } from "next/server";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { apiError, json } from "@/lib/server/api";
import { idSchema } from "@/lib/server/validation";
import { processCampaign, resumeCampaign } from "@/lib/server/campaigns";
import { rateLimit } from "@/lib/server/rate-limit";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const user = await requireUser(req);
    const id = idSchema.parse((await params).id);
    await rateLimit(user.uid, "campaign-resume", 10);
    await resumeCampaign(user.uid, id);
    after(async () => {
      try { await processCampaign(id); }
      catch (error) { console.error("Campaign resume deferred to worker", { campaignId: id, error }); }
    });
    return json({ success: true, campaignId: id, status: "queued" }, 202);
  } catch (error) { return apiError(error); }
}
