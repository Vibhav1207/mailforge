import { NextRequest } from "next/server";
import { z } from "zod";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { getAdminDb, isFirebaseAdminConfigured } from "@/lib/firebase/admin";
import { getMongoDb, isMongoConfigured } from "@/lib/mongodb";
import { apiError, json, parseJson } from "@/lib/server/api";
import { idSchema } from "@/lib/server/validation";
import { getOwned } from "@/lib/server/data";
import { cancelCampaign } from "@/lib/server/campaigns";
import { ApiError } from "@/lib/server/errors";

type Context = { params: Promise<{ id: string }> };

export async function GET(req: NextRequest, { params }: Context) {
  try {
    const user = await requireUser(req);
    return json({ campaign: await getOwned("campaigns", (await params).id, user.uid) });
  } catch (error) { return apiError(error); }
}

export async function PATCH(req: NextRequest, { params }: Context) {
  try {
    const user = await requireUser(req);
    const id = idSchema.parse((await params).id);
    await parseJson(req, z.object({ status: z.literal("cancelled") }), 1000);
    await cancelCampaign(user.uid, id);
    return json({ campaign: await getOwned("campaigns", id, user.uid) });
  } catch (error) { return apiError(error); }
}

export async function DELETE(req: NextRequest, { params }: Context) {
  try {
    const user = await requireUser(req);
    const id = idSchema.parse((await params).id);

    if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
      const db = await getMongoDb();
      const doc = await db.collection("campaigns").findOne({ _id: id as any });
      if (!doc || (doc as any).userId !== user.uid) throw new ApiError(404, "Campaign not found.", "NOT_FOUND");
      await db.collection("campaigns").deleteOne({ _id: id as any });
      await db.collection("campaignRecipients").deleteMany({ campaignId: id, userId: user.uid });
      return json({ success: true });
    }

    const db = getAdminDb();
    const ref = db.collection("campaigns").doc(id);
    const jobRef = db.collection("campaignJobs").doc(id);
    await db.runTransaction(async (tx) => {
      const [doc, job] = await Promise.all([tx.get(ref), tx.get(jobRef)]);
      if (!doc.exists || doc.data()?.userId !== user.uid) throw new ApiError(404, "Campaign not found.", "NOT_FOUND");
      if (["running", "ready"].includes(job.data()?.state) || ["queued", "sending", "scheduled"].includes(doc.data()?.status)) throw new ApiError(409, "Cancel this campaign before deleting it.", "CAMPAIGN_ACTIVE");
      tx.delete(ref);
      if (job.exists) tx.delete(jobRef);
    });
    for (const collection of ["campaignRecipients", "emailEvents"]) {
      while (true) {
        const docs = await db.collection(collection).where("campaignId", "==", id).where("userId", "==", user.uid).limit(400).get();
        if (docs.empty) break;
        const batch = db.batch();
        docs.docs.forEach((doc) => batch.delete(doc.ref));
        await batch.commit();
      }
    }
    return json({ success: true });
  } catch (error) { return apiError(error); }
}
