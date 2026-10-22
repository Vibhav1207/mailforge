import { randomUUID } from "node:crypto";
import { NextRequest } from "next/server";
import { ObjectId } from "mongodb";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { getMongoDb } from "@/lib/mongodb";
import { apiError, json, parseJson } from "@/lib/server/api";
import { folderSchema, templateSchema } from "@/lib/server/validation";

export async function GET(req: NextRequest) {
  try {
    const user = await requireUser(req);
    const folder = req.nextUrl.searchParams.get("folder");
    const db = await getMongoDb();
    const docs = await db.collection("email_templates").find({ userId: user.uid, ...(folder && folder !== "all" ? { folder: folderSchema.parse(folder) } : {}) }).sort({ createdAt: -1 }).limit(1000).toArray();
    return json({ templates: docs.map(({ _id, ...doc }) => ({ ...doc, id: doc.id || _id.toHexString() })), mongoConnected: true });
  } catch (error) { return apiError(error); }
}

export async function POST(req: NextRequest) {
  try {
    const user = await requireUser(req);
    const input = await parseJson(req, templateSchema, 650_000);
    const id = input.id || `tpl_${randomUUID()}`;
    const collection = (await getMongoDb()).collection("email_templates");
    const filter = { userId: user.uid, $or: [{ id }, ...(ObjectId.isValid(id) ? [{ _id: new ObjectId(id) }] : [])] };
    const now = new Date().toISOString();
    const template = await collection.findOneAndUpdate(filter, {
      $set: { ...input, id, userId: user.uid, updatedAt: now }, $setOnInsert: { createdAt: now },
    }, { upsert: true, returnDocument: "after" });
    const { _id: _unused, ...saved } = template!;
    return json({ success: true, template: saved });
  } catch (error) { return apiError(error); }
}
