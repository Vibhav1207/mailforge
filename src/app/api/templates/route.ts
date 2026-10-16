import { NextRequest, NextResponse } from "next/server";
import { verifyServerAuth, unauthorizedResponse } from "@/lib/firebase/auth-middleware";
import { getMongoDb, isMongoConfigured } from "@/lib/mongodb";
import { EmailTemplate } from "@/types";

export async function GET(req: NextRequest) {
  try {
    const user = await verifyServerAuth(req);
    if (!user) {
      return unauthorizedResponse();
    }

    const { searchParams } = new URL(req.url);
    const folder = searchParams.get("folder");

    let templates: EmailTemplate[] = [];

    if (isMongoConfigured()) {
      try {
        const db = await getMongoDb();
        const collection = db.collection("email_templates");
        const query: any = { userId: user.uid };
        if (folder && folder !== "all") {
          query.folder = folder;
        }

        const docs = await collection.find(query).sort({ createdAt: -1 }).toArray();
        templates = docs.map((d: any) => ({
          id: d._id.toString(),
          userId: d.userId,
          name: d.name,
          subject: d.subject,
          category: d.category || "custom",
          description: d.description || "",
          imageUrl: d.imageUrl || undefined,
          folder: d.folder || "general",
          htmlContent: d.htmlContent,
          textContent: d.textContent || "",
          createdAt: d.createdAt,
        }));
      } catch (mongoErr: any) {
        console.warn("MongoDB templates fetch warning:", mongoErr.message);
      }
    }

    return NextResponse.json({
      success: true,
      templates,
      mongoConnected: isMongoConfigured(),
    });
  } catch (err: any) {
    console.error("Templates API GET error:", err);
    return NextResponse.json(
      { error: err?.message || "Failed to fetch templates" },
      { status: 500 }
    );
  }
}

export async function POST(req: NextRequest) {
  try {
    const user = await verifyServerAuth(req);
    if (!user) {
      return unauthorizedResponse();
    }

    const body = await req.json();
    const { id, name, subject, category, description, imageUrl, folder, htmlContent, textContent } = body;

    if (!name || !subject || !htmlContent) {
      return NextResponse.json(
        { error: "Missing required fields (name, subject, htmlContent)" },
        { status: 400 }
      );
    }

    const templateData: EmailTemplate = {
      id: id || `tpl_${Date.now()}`,
      userId: user.uid,
      name,
      subject,
      category: category || "custom",
      description: description || "",
      imageUrl: imageUrl || undefined,
      folder: folder || "general",
      htmlContent,
      textContent: textContent || "",
      createdAt: new Date().toISOString(),
    };

    if (isMongoConfigured()) {
      try {
        const db = await getMongoDb();
        const collection = db.collection("email_templates");
        await collection.updateOne(
          { id: templateData.id, userId: user.uid },
          { $set: templateData },
          { upsert: true }
        );
      } catch (mongoErr: any) {
        console.warn("MongoDB template save warning:", mongoErr.message);
      }
    }

    return NextResponse.json({
      success: true,
      template: templateData,
      message: "Template saved successfully",
    });
  } catch (err: any) {
    console.error("Templates API POST error:", err);
    return NextResponse.json(
      { error: err?.message || "Failed to save template" },
      { status: 500 }
    );
  }
}
