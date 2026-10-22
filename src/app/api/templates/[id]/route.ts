import { NextRequest } from "next/server";
import { ObjectId } from "mongodb";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { getMongoDb } from "@/lib/mongodb";
import { apiError, json } from "@/lib/server/api";
import { idSchema } from "@/lib/server/validation";
import { ApiError } from "@/lib/server/errors";

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const user = await requireUser(req);
    const id = idSchema.parse((await params).id);
    const result = await (await getMongoDb()).collection("email_templates").deleteOne({ userId: user.uid, $or: [{ id }, ...(ObjectId.isValid(id) ? [{ _id: new ObjectId(id) }] : [])] });
    if (!result.deletedCount) throw new ApiError(404, "Template not found.", "NOT_FOUND");
    return json({ success: true });
  } catch (error) { return apiError(error); }
}
