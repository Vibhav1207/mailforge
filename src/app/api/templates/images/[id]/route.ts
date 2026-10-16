import { NextRequest, NextResponse } from "next/server";
import { getTemplateImageByIdFromMongo, deleteTemplateImageFromMongo } from "@/lib/mongodb";
import { verifyServerAuth, unauthorizedResponse } from "@/lib/firebase/auth-middleware";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    if (!id) {
      return new NextResponse("Not Found", { status: 404 });
    }

    const imgDoc = await getTemplateImageByIdFromMongo(id);
    if (!imgDoc || !imgDoc.dataBase64) {
      return new NextResponse("Image Not Found", { status: 404 });
    }

    const buffer = Buffer.from(imgDoc.dataBase64, "base64");
    const contentType = imgDoc.contentType || "image/png";

    return new NextResponse(buffer, {
      status: 200,
      headers: {
        "Content-Type": contentType,
        "Content-Length": buffer.length.toString(),
        "Cache-Control": "public, max-age=31536000, immutable",
      },
    });
  } catch (err: any) {
    console.error("Serve template image error:", err);
    return new NextResponse("Internal Server Error", { status: 500 });
  }
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const user = await verifyServerAuth(req);
    if (!user) {
      return unauthorizedResponse();
    }

    const { id } = await params;
    if (!id) {
      return NextResponse.json({ error: "Missing image id" }, { status: 400 });
    }

    const success = await deleteTemplateImageFromMongo(id, user.uid);
    if (!success) {
      return NextResponse.json({ error: "Image not found or delete failed" }, { status: 404 });
    }

    return NextResponse.json({ success: true, message: "Template image deleted" });
  } catch (err: any) {
    console.error("Delete template image error:", err);
    return NextResponse.json({ error: err?.message || "Failed to delete" }, { status: 500 });
  }
}
