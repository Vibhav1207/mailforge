import { NextRequest } from "next/server";
import { getAdminDb } from "@/lib/firebase/admin";
import { apiError, json } from "@/lib/server/api";
import { requireCron } from "@/lib/server/cron-auth";
import { processCampaign } from "@/lib/server/campaigns";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function GET(req: NextRequest) {
  try {
    requireCron(req);
    const db = getAdminDb();
    const start = Date.now();
    const jobs = await db.collection("campaignJobs").where("state", "in", ["ready", "running"]).where("nextRunAt", "<=", start).orderBy("nextRunAt").limit(5).get();
    let processed = 0;
    let failed = 0;
    for (const job of jobs.docs) {
      if (Date.now() - start > 35_000) break;
      try { await processCampaign(job.id, Math.max(1000, 35_000 - (Date.now() - start))); processed++; }
      catch { failed++; }
    }
    await db.collection("system").doc("campaignWorker").set({ lastRunAt: new Date().toISOString(), processed, failed });
    return json({ success: failed === 0, processed, failed }, failed ? 503 : 200);
  } catch (error) { return apiError(error); }
}
