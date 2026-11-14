import { NextRequest } from "next/server";
import { z } from "zod";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { saveTemplateImageToMongo, getTemplateImagesFromMongo } from "@/lib/mongodb";
import { apiError, json, parseJson, readBody } from "@/lib/server/api";
import { folderSchema } from "@/lib/server/validation";
import { decodeImageBase64, MAX_IMAGE_BYTES, validateImage } from "@/lib/server/images";
import { rateLimit } from "@/lib/server/rate-limit";
import { ApiError } from "@/lib/server/errors";
import { appUrl } from "@/lib/server/config";

export const runtime = "nodejs";
const schema = z.object({ folder: folderSchema, filename: z.string().max(255).default("image"), contentType: z.string().max(80).optional(), dataBase64: z.string().max(4_194_400) });

export async function POST(req: NextRequest) {
  try {
    const user = await requireUser(req);
    await rateLimit(user.uid, "image-upload", 20);
    appUrl();
    let folder: string;
    let filename: string;
    let declared: string | undefined;
    let bytes: Buffer;
    if (req.headers.get("content-type")?.startsWith("multipart/form-data")) {
      let form: FormData;
      try {
        form = await req.formData();
      } catch {
        throw new ApiError(400, "Invalid multipart upload.", "INVALID_IMAGE");
      }
      const file = form.get("file");
      if (!(file instanceof File)) throw new ApiError(400, "Choose an image file to upload.", "INVALID_IMAGE");
      if (file.size > MAX_IMAGE_BYTES) throw new ApiError(413, "Images must be 5 MB or smaller.", "PAYLOAD_TOO_LARGE");
      folder = folderSchema.parse(form.get("folder") || "general");
      filename = file.name;
      declared = file.type || undefined;
      bytes = Buffer.from(await file.arrayBuffer());
    } else {
      const input = await parseJson(req, schema, MAX_IMAGE_BYTES + 65_536);
      folder = input.folder;
      filename = input.filename;
      declared = input.contentType;
      bytes = decodeImageBase64(input.dataBase64);
    }
    const contentType = validateImage(bytes, declared);
    filename = filename.replace(/[\x00-\x1f\x7f/\\]/g, "_").slice(0, 255) || "image";
    const image = await saveTemplateImageToMongo({ userId: user.uid, folder, filename, contentType, size: bytes.length, bytes });
    return json({ success: true, image }, 201);
  } catch (error) { return apiError(error); }
}

export async function GET(req: NextRequest) {
  try {
    const user = await requireUser(req);
    const folder = req.nextUrl.searchParams.get("folder");
    return json({ images: await getTemplateImagesFromMongo(user.uid, folder ? folderSchema.parse(folder) : undefined), mongoConfigured: true });
  } catch (error) { return apiError(error); }
}
