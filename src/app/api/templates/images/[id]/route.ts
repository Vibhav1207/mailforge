import { NextRequest, NextResponse } from "next/server";
import { getTemplateImageByIdFromMongo, deleteTemplateImageFromMongo } from "@/lib/mongodb";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { apiError, json } from "@/lib/server/api";
import { validateImage } from "@/lib/server/images";
import { ApiError } from "@/lib/server/errors";

type Context = { params: Promise<{ id: string }> };

export async function GET(_req: NextRequest, { params }: Context) {
  try {
    const image = await getTemplateImageByIdFromMongo((await params).id);
    if (!image) throw new ApiError(404, "Image not found.", "NOT_FOUND");
    const bytes = image.data ? Buffer.from(image.data.buffer) : Buffer.from(image.dataBase64 || "", "base64");
    const contentType = validateImage(bytes, image.contentType);
    return new NextResponse(new Uint8Array(bytes), { headers: {
      "Content-Type": contentType, "Content-Length": String(bytes.length),
      "Cache-Control": "public, max-age=86400", "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'none'; sandbox", "Content-Disposition": "inline",
    } });
  } catch (error) { return apiError(error); }
}

export async function DELETE(req: NextRequest, { params }: Context) {
  try {
    const user = await requireUser(req);
    if (!await deleteTemplateImageFromMongo((await params).id, user.uid)) throw new ApiError(404, "Image not found.", "NOT_FOUND");
    return json({ success: true });
  } catch (error) { return apiError(error); }
}
