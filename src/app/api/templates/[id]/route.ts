import { NextRequest } from "next/server";
import { ObjectId } from "mongodb";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { getMongoDb } from "@/lib/mongodb";
import { apiError, json } from "@/lib/server/api";
import { idSchema } from "@/lib/server/validation";
import { ApiError } from "@/lib/server/errors";
import { buildSafeOwnershipFilter } from "@/lib/server/mongodb-security";

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const user = await requireUser(req);
    const id = idSchema.parse((await params).id);
    const filter = buildSafeOwnershipFilter(id, user.uid);
    const result = await (await getMongoDb()).collection("email_templates").deleteOne(filter);
    if (!result.deletedCount) throw new ApiError(404, "Template not found.", "NOT_FOUND");
    return json({ success: true });
  } catch (error) { return apiError(error); }
}
