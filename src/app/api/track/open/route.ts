import { NextRequest, NextResponse } from "next/server";
import { adminDb } from "@/lib/firebase/admin";

// 1x1 transparent GIF buffer
const TRANSPARENT_PIXEL = Buffer.from(
  "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",
  "base64"
);

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const campaignId = searchParams.get("cid");
  const recipientId = searchParams.get("rid");

  if (campaignId && adminDb) {
    try {
      // 1. Update recipient record if present
      if (recipientId) {
        const rcpRef = adminDb.collection("campaignRecipients").doc(recipientId);
        const rcpDoc = await rcpRef.get();
        if (rcpDoc.exists) {
          const currentOpens = rcpDoc.data()?.openCount || 0;
          await rcpRef.update({
            openCount: currentOpens + 1,
            openedAt: new Date().toISOString(),
          });
        }
      }

      // 2. Increment campaign stats.opened
      const cmpRef = adminDb.collection("campaigns").doc(campaignId);
      const cmpDoc = await cmpRef.get();
      if (cmpDoc.exists) {
        const stats = cmpDoc.data()?.stats || {};
        await cmpRef.update({
          "stats.opened": (stats.opened || 0) + 1,
        });
      }

      // 3. Log event
      await adminDb.collection("emailEvents").add({
        campaignId,
        recipientId: recipientId || null,
        event: "opened",
        timestamp: new Date().toISOString(),
        userAgent: req.headers.get("user-agent") || null,
        ip: req.headers.get("x-forwarded-for") || null,
      });
    } catch (err) {
      console.warn("Track open error:", err);
    }
  }

  // Always return the 1x1 transparent image with no caching
  return new NextResponse(TRANSPARENT_PIXEL, {
    status: 200,
    headers: {
      "Content-Type": "image/gif",
      "Content-Length": TRANSPARENT_PIXEL.length.toString(),
      "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0",
      Pragma: "no-cache",
      Expires: "0",
    },
  });
}
