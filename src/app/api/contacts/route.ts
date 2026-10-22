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
import { buildSafeOwnershipFilter, sanitizeMongoInput } from "@/lib/server/mongodb-security";

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

    const cleanInput = sanitizeMongoInput(input);

    if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
      const db = await getMongoDb();
      const filter = buildSafeOwnershipFilter(cleanInput.id, user.uid);
      const existing = await db.collection("contacts").findOne(filter);
      if (existing && (existing as any).userId !== user.uid) throw new ApiError(404, "Contact not found.", "NOT_FOUND");
      const suppression = await db.collection("suppressionLists").findOne({ _id: suppressionId(user.uid, cleanInput.email) as any, userId: user.uid });
      const now = new Date().toISOString();
      const status = suppression ? ((suppression as any).reason === "unsubscribe" ? "unsubscribed" : "suppressed") : cleanInput.status;
      const value = stripUndefined({
        id: cleanInput.id,
        email: cleanInput.email,
        firstName: cleanInput.firstName,
        lastName: cleanInput.lastName,
        company: cleanInput.company,
        customFields: cleanInput.customFields,
        status,
        listIds: cleanInput.listIds,
        tags: cleanInput.tags,
        suppressionReason: cleanInput.suppressionReason,
        userId: user.uid,
        createdAt: (existing as any)?.createdAt || now,
        updatedAt: now,
      });
      await db.collection("contacts").updateOne(
        { _id: cleanInput.id as any, userId: user.uid },
        { $set: value, $setOnInsert: { createdAt: now } },
        { upsert: true }
      );
      if (status !== "active" && !suppression) {
        await db.collection("suppressionLists").updateOne(
          { _id: suppressionId(user.uid, cleanInput.email) as any, userId: user.uid },
          { $set: { userId: user.uid, email: cleanInput.email, reason: status === "unsubscribed" ? "unsubscribe" : "manual", note: cleanInput.suppressionReason || "", createdAt: now } },
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
