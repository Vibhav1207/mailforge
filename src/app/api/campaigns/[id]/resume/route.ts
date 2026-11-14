import { NextRequest } from "next/server";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { apiError, json } from "@/lib/server/api";
import { idSchema } from "@/lib/server/validation";
import { processCampaign, resumeCampaign } from "@/lib/server/campaigns";
import { getOwned } from "@/lib/server/data";
import { rateLimit } from "@/lib/server/rate-limit";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const user = await requireUser(req);
    const id = idSchema.parse((await params).id);
    await rateLimit(user.uid, "campaign-resume", 120);

    const existing = (await getOwned("campaigns", id, user.uid).catch(() => null)) as any;
    if (existing && ["completed", "completed_with_errors", "failed", "cancelled"].includes(existing.status)) {
      return json({
        success: true,
        campaignId: id,
        campaign: existing,
        finished: true,
        status: existing.status,
        stats: existing.stats,
      });
    }

    try {
      await resumeCampaign(user.uid, id);
    } catch (resumeErr: any) {
      if (resumeErr?.code !== "CAMPAIGN_NOT_RESUMABLE") throw resumeErr;
    }

    const result = await processCampaign(id, 15_000);
    const updated = (await getOwned("campaigns", id, user.uid).catch(() => null)) as any;
    const current = updated || existing;

    return json({
      success: true,
      campaignId: id,
      campaign: current,
      finished: result?.finished ?? false,
      status: current?.status || "queued",
      stats: current?.stats || { sent: 0, failed: 0, total: 0 },
    });
  } catch (error) { return apiError(error); }
}
