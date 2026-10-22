import { FieldPath, type DocumentData } from "firebase-admin/firestore";
import { getAdminDb, isFirebaseAdminConfigured } from "@/lib/firebase/admin";
import { getMongoDb, isMongoConfigured } from "@/lib/mongodb";
import { ApiError } from "./errors";
import { idSchema } from "./validation";

export async function getOwned(collection: string, id: string, userId: string): Promise<DocumentData> {
  idSchema.parse(id);

  if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
    const db = await getMongoDb();
    const doc = await db.collection(collection).findOne({ _id: id as any });
    if (!doc || (doc as any).userId !== userId) throw new ApiError(404, "Resource not found.", "NOT_FOUND");
    const { _id, ...rest } = doc as any;
    return { ...rest, id };
  }

  const doc = await getAdminDb().collection(collection).doc(id).get();
  if (!doc.exists || doc.data()?.userId !== userId) throw new ApiError(404, "Resource not found.", "NOT_FOUND");
  return { ...doc.data(), id: doc.id };
}

export async function listOwned(collection: string, userId: string, searchParams: URLSearchParams) {
  const pageSize = Math.min(500, Math.max(1, Number(searchParams.get("limit")) || 500));
  const cursor = searchParams.get("cursor");

  if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
    const db = await getMongoDb();
    const filter: Record<string, any> = { userId };
    if (cursor) filter._id = { $gt: cursor };
    const docs = await db.collection(collection).find(filter).sort({ _id: 1 }).limit(pageSize).toArray();
    const items = docs.map((doc: any) => {
      const { _id, ...rest } = doc;
      return { ...rest, id: _id.toString() };
    });
    return { items, nextCursor: items.length === pageSize ? items[items.length - 1].id : null };
  }

  let query = getAdminDb().collection(collection).where("userId", "==", userId).orderBy(FieldPath.documentId()).limit(Math.floor(pageSize));
  if (cursor) query = query.startAfter(idSchema.parse(cursor));
  const snap = await query.get();
  return { items: snap.docs.map((doc) => ({ ...doc.data(), id: doc.id })), nextCursor: snap.size === pageSize ? snap.docs.at(-1)!.id : null };
}
