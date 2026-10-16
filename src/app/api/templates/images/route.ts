import { NextRequest, NextResponse } from "next/server";
import { verifyServerAuth, unauthorizedResponse } from "@/lib/firebase/auth-middleware";
import {
  saveTemplateImageToMongo,
  getTemplateImagesFromMongo,
  isMongoConfigured,
} from "@/lib/mongodb";

export async function POST(req: NextRequest) {
  try {
    const user = await verifyServerAuth(req);
    if (!user) {
      return unauthorizedResponse();
    }

    const contentType = req.headers.get("content-type") || "";

    let folder = "general";
    let filename = `image_${Date.now()}.png`;
    let fileContentType = "image/png";
    let dataBase64 = "";
    let size = 0;

    if (contentType.includes("multipart/form-data")) {
      const formData = await req.formData();
      const file = formData.get("file") as File | null;
      folder = (formData.get("folder") as string) || "general";

      if (!file) {
        return NextResponse.json({ error: "No image file provided" }, { status: 400 });
      }

      filename = file.name || filename;
      fileContentType = file.type || fileContentType;
      size = file.size;

      // Limit image size to 5MB
      if (size > 5 * 1024 * 1024) {
        return NextResponse.json({ error: "Image size exceeds 5MB limit" }, { status: 400 });
      }

      const arrayBuffer = await file.arrayBuffer();
      const buffer = Buffer.from(arrayBuffer);
      dataBase64 = buffer.toString("base64");
    } else {
      const body = await req.json();
      folder = body.folder || "general";
      filename = body.filename || filename;
      fileContentType = body.contentType || fileContentType;
      dataBase64 = body.dataBase64 || "";

      if (!dataBase64) {
        return NextResponse.json({ error: "Missing base64 image data" }, { status: 400 });
      }

      // If dataBase64 has data URI prefix (data:image/png;base64,...), strip it
      if (dataBase64.includes(";base64,")) {
        const parts = dataBase64.split(";base64,");
        const match = parts[0].match(/data:(.*)/);
        if (match && match[1]) {
          fileContentType = match[1];
        }
        dataBase64 = parts[1];
      }

      size = Math.round((dataBase64.length * 3) / 4);
    }

    const saved = await saveTemplateImageToMongo({
      userId: user.uid,
      folder,
      filename,
      contentType: fileContentType,
      size,
      dataBase64,
    });

    return NextResponse.json({
      success: true,
      image: saved,
      message: "Template image saved successfully to MongoDB folder",
    });
  } catch (err: any) {
    console.error("Template image upload error:", err);
    return NextResponse.json(
      { error: err?.message || "Failed to save template image to MongoDB" },
      { status: 500 }
    );
  }
}

export async function GET(req: NextRequest) {
  try {
    const user = await verifyServerAuth(req);
    if (!user) {
      return unauthorizedResponse();
    }

    const { searchParams } = new URL(req.url);
    const folder = searchParams.get("folder") || undefined;

    const images = await getTemplateImagesFromMongo(user.uid, folder);

    return NextResponse.json({
      success: true,
      images,
      mongoConfigured: isMongoConfigured(),
    });
  } catch (err: any) {
    console.error("Get template images error:", err);
    return NextResponse.json(
      { error: err?.message || "Failed to fetch template images" },
      { status: 500 }
    );
  }
}
