import { getAdminDb, isFirebaseAdminConfigured } from "@/lib/firebase/admin";
import { getMongoDb, isMongoConfigured } from "@/lib/mongodb";
import { processCampaign } from "./campaigns";

export interface CampaignWorkerResult {
  processed: number;
  failed: number;
}

export async function runCampaignWorker(budgetMs = 35_000): Promise<CampaignWorkerResult> {
  const start = Date.now();
  let processed = 0;
  let failed = 0;

  if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
    const db = await getMongoDb();
    const jobs = await db.collection("campaignJobs")
      .find({ state: { $in: ["ready", "running"] }, nextRunAt: { $lte: start } })
      .sort({ nextRunAt: 1 })
      .limit(5)
      .toArray();

    for (const job of jobs) {
      if (Date.now() - start > budgetMs) break;
      try {
        await processCampaign(String(job._id), Math.max(1000, budgetMs - (Date.now() - start)));
        processed++;
      } catch {
        failed++;
      }
    }

    await db.collection("system").updateOne(
      { _id: "campaignWorker" as any },
      { $set: { lastRunAt: new Date().toISOString(), processed, failed } },
      { upsert: true },
    );
  } else {
    const db = getAdminDb();
    const jobs = await db.collection("campaignJobs")
      .where("state", "in", ["ready", "running"])
      .where("nextRunAt", "<=", start)
      .orderBy("nextRunAt")
      .limit(5)
      .get();

    for (const job of jobs.docs) {
      if (Date.now() - start > budgetMs) break;
      try {
        await processCampaign(job.id, Math.max(1000, budgetMs - (Date.now() - start)));
        processed++;
      } catch {
        failed++;
      }
    }

    await db.collection("system").doc("campaignWorker").set({
      lastRunAt: new Date().toISOString(),
      processed,
      failed,
    });
  }

  return { processed, failed };
}
