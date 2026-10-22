import { NextRequest } from "next/server";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { getAdminDb, isFirebaseAdminConfigured } from "@/lib/firebase/admin";
import { getMongoDb, isMongoConfigured } from "@/lib/mongodb";
import { apiError, json, parseJson } from "@/lib/server/api";
import { contactSchema } from "@/lib/server/validation";
import { listOwned } from "@/lib/server/data";
import { suppressionId } from "@/lib/server/suppression";
import { stripUndefined } from "@/lib/server/settings";
import { ApiError } from "@/lib/server/errors";

export async function GET(req: NextRequest) {
  try {
    const user = await requireUser(req);
    const { items, nextCursor } = await listOwned("contacts", user.uid, req.nextUrl.searchParams);
    return json({ contacts: items, nextCursor });
  } catch (error) { return apiError(error); }
}

export async function POST(req: NextRequest) {
  try {
    const user = await requireUser(req);
    const input = await parseJson(req, contactSchema, 150_000);

    if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
      const db = await getMongoDb();
      const existing = await db.collection("contacts").findOne({ _id: input.id as any });
      if (existing && (existing as any).userId !== user.uid) throw new ApiError(404, "Contact not found.", "NOT_FOUND");
      const suppression = await db.collection("suppressionLists").findOne({ _id: suppressionId(user.uid, input.email) as any });
      const now = new Date().toISOString();
      const status = suppression ? ((suppression as any).reason === "unsubscribe" ? "unsubscribed" : "suppressed") : input.status;
      const value = stripUndefined({ ...input, status, userId: user.uid, createdAt: (existing as any)?.createdAt || now, updatedAt: now });
      await db.collection("contacts").updateOne({ _id: input.id as any }, { $set: value }, { upsert: true });
      if (status !== "active" && !suppression) {
        await db.collection("suppressionLists").updateOne(
          { _id: suppressionId(user.uid, input.email) as any },
          { $set: { userId: user.uid, email: input.email, reason: status === "unsubscribed" ? "unsubscribe" : "manual", note: input.suppressionReason || "", createdAt: now } },
          { upsert: true }
        );
      }
      return json({ contact: value });
    }

    const db = getAdminDb();
    const ref = db.collection("contacts").doc(input.id);
    const supRef = db.collection("suppressionLists").doc(suppressionId(user.uid, input.email));
    const contact = await db.runTransaction(async (tx) => {
      const [existing, suppression] = await Promise.all([tx.get(ref), tx.get(supRef)]);
      if (existing.exists && existing.data()?.userId !== user.uid) throw new ApiError(404, "Contact not found.", "NOT_FOUND");
      const now = new Date().toISOString();
      const status = suppression.exists ? (suppression.data()?.reason === "unsubscribe" ? "unsubscribed" : "suppressed") : input.status;
      const value = stripUndefined({ ...input, status, userId: user.uid, createdAt: existing.data()?.createdAt || now, updatedAt: now });
      tx.set(ref, value);
      if (status !== "active" && !suppression.exists) {
        tx.set(supRef, { userId: user.uid, email: input.email, reason: status === "unsubscribed" ? "unsubscribe" : "manual", note: input.suppressionReason || "", createdAt: now });
      }
      return value;
    });
    return json({ contact });
  } catch (error) { return apiError(error); }
}
