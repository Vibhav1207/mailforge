import { randomUUID } from "node:crypto";
import { NextRequest } from "next/server";
import { ObjectId } from "mongodb";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { getMongoDb } from "@/lib/mongodb";
import { apiError, json, parseJson } from "@/lib/server/api";
import { folderSchema, templateSchema } from "@/lib/server/validation";
import { buildSafeOwnershipFilter, parseSafePagination, sanitizeMongoInput, allowlistFields } from "@/lib/server/mongodb-security";

const ALLOWED_TEMPLATE_FIELDS = [
  "name",
  "subject",
  "category",
  "description",
  "folder",
  "imageUrl",
  "htmlContent",
  "textContent",
] as const;

export async function GET(req: NextRequest) {
  try {
    const user = await requireUser(req);
    const folder = req.nextUrl.searchParams.get("folder");
    const { limit } = parseSafePagination(req.nextUrl.searchParams, 50, 100);
    const db = await getMongoDb();
    const query: Record<string, unknown> = {
      userId: user.uid,
      ...(folder && folder !== "all" ? { folder: folderSchema.parse(folder) } : {}),
    };

    const docs = await db
      .collection("email_templates")
      .find(query)
      .sort({ createdAt: -1 })
      .limit(limit)
      .toArray();

    return json({
      templates: docs.map(({ _id, ...doc }) => ({ ...doc, id: doc.id || _id.toHexString() })),
      mongoConnected: true,
    });
  } catch (error) {
    return apiError(error);
  }
}

export async function POST(req: NextRequest) {
  try {
    const user = await requireUser(req);
    const input = await parseJson(req, templateSchema, 650_000);
    const cleanInput = sanitizeMongoInput(input);
    const id = cleanInput.id || `tpl_${randomUUID()}`;
    const collection = (await getMongoDb()).collection("email_templates");
    const filter = buildSafeOwnershipFilter(id, user.uid);
    const now = new Date().toISOString();

    const allowedData = allowlistFields(cleanInput, ALLOWED_TEMPLATE_FIELDS);

    const template = await collection.findOneAndUpdate(
      filter,
      {
        $set: { ...allowedData, id, userId: user.uid, updatedAt: now },
        $setOnInsert: { createdAt: now },
      },
      { upsert: true, returnDocument: "after" }
    );
    const { _id: _unused, ...saved } = template!;
    return json({ success: true, template: saved });
  } catch (error) {
    return apiError(error);
  }
}
