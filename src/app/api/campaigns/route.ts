import { NextRequest } from "next/server";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { getAdminDb, isFirebaseAdminConfigured } from "@/lib/firebase/admin";
import { getMongoDb, isMongoConfigured } from "@/lib/mongodb";
import { apiError, json, parseJson } from "@/lib/server/api";
import { listOwned } from "@/lib/server/data";
import { draftSchema } from "@/lib/server/validation";
import { stripUndefined } from "@/lib/server/settings";
import { ApiError } from "@/lib/server/errors";
import { buildSafeOwnershipFilter, sanitizeMongoInput } from "@/lib/server/mongodb-security";

export async function GET(req: NextRequest) {
  try {
    const user = await requireUser(req);
    const { items, nextCursor } = await listOwned("campaigns", user.uid, req.nextUrl.searchParams);
    return json({ campaigns: items, nextCursor });
  } catch (error) { return apiError(error); }
}

export async function POST(req: NextRequest) {
  try {
    const user = await requireUser(req);
    const input = await parseJson(req, draftSchema, 900_000);
    const cleanInput = sanitizeMongoInput(input);

    if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
      const db = await getMongoDb();
      const filter = buildSafeOwnershipFilter(cleanInput.id, user.uid);
      const old = await db.collection("campaigns").findOne(filter);
      if (old && (old as any).userId !== user.uid) throw new ApiError(404, "Campaign not found.", "NOT_FOUND");
      if (old && (old as any).status !== "draft") throw new ApiError(409, "Only draft campaigns can be edited.", "CAMPAIGN_ALREADY_QUEUED");
      const now = new Date().toISOString();
      const count = cleanInput.draftRecipients?.length ?? cleanInput.recipientCount;
      const value = stripUndefined({
        ...cleanInput,
        userId: user.uid,
        recipientCount: count,
        stats: { total: count, sent: 0, delivered: 0, failed: 0, bounced: 0, unsubscribed: 0 },
        createdAt: (old as any)?.createdAt || now,
        updatedAt: now,
      });
      await db.collection("campaigns").updateOne(
        { _id: cleanInput.id as any, userId: user.uid },
        { $set: value, $setOnInsert: { createdAt: now } },
        { upsert: true }
      );
      return json({ campaign: value });
    }

    const db = getAdminDb();
    const ref = db.collection("campaigns").doc(input.id);
    const campaign = await db.runTransaction(async (tx) => {
      const old = await tx.get(ref);
      if (old.exists && old.data()?.userId !== user.uid) throw new ApiError(404, "Campaign not found.", "NOT_FOUND");
      if (old.exists && old.data()?.status !== "draft") throw new ApiError(409, "Only draft campaigns can be edited.", "CAMPAIGN_ALREADY_QUEUED");
      const now = new Date().toISOString();
      const count = input.draftRecipients?.length ?? input.recipientCount;
      const value = stripUndefined({ ...input, userId: user.uid, recipientCount: count, stats: { total: count, sent: 0, delivered: 0, failed: 0, bounced: 0, unsubscribed: 0 }, createdAt: old.data()?.createdAt || now, updatedAt: now });
      tx.set(ref, value);
      return value;
    });
    return json({ campaign });
  } catch (error) { return apiError(error); }
}
