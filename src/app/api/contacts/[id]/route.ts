import { NextRequest } from "next/server";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { getAdminDb, isFirebaseAdminConfigured } from "@/lib/firebase/admin";
import { getMongoDb, isMongoConfigured } from "@/lib/mongodb";
import { apiError, json } from "@/lib/server/api";
import { idSchema } from "@/lib/server/validation";
import { ApiError } from "@/lib/server/errors";
import { buildSafeOwnershipFilter } from "@/lib/server/mongodb-security";

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const user = await requireUser(req);
    const id = idSchema.parse((await params).id);

    if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
      const db = await getMongoDb();
      const filter = buildSafeOwnershipFilter(id, user.uid);
      const doc = await db.collection("contacts").findOne(filter);
      if (!doc || (doc as any).userId !== user.uid) throw new ApiError(404, "Contact not found.", "NOT_FOUND");
      await db.collection("contacts").deleteOne(filter);
      return json({ success: true });
    }

    const db = getAdminDb();
    const ref = db.collection("contacts").doc(id);
    await db.runTransaction(async (tx) => {
      const doc = await tx.get(ref);
      if (!doc.exists || doc.data()?.userId !== user.uid) throw new ApiError(404, "Contact not found.", "NOT_FOUND");
      tx.delete(ref);
    });
    return json({ success: true });
  } catch (error) { return apiError(error); }
}
