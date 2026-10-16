import { NextRequest, NextResponse } from "next/server";
import { adminDb } from "@/lib/firebase/admin";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const campaignId = searchParams.get("cid");
  const recipientId = searchParams.get("rid");
  const targetUrl = searchParams.get("url");

  if (!targetUrl) {
    return NextResponse.redirect(new URL("/", req.url));
  }

  // Record click event in Firestore
  if (campaignId && adminDb) {
    try {
      if (recipientId) {
        const rcpRef = adminDb.collection("campaignRecipients").doc(recipientId);
        const rcpDoc = await rcpRef.get();
        if (rcpDoc.exists) {
          const currentClicks = rcpDoc.data()?.clickCount || 0;
          await rcpRef.update({
            clickCount: currentClicks + 1,
            clickedAt: new Date().toISOString(),
          });
        }
      }

      const cmpRef = adminDb.collection("campaigns").doc(campaignId);
      const cmpDoc = await cmpRef.get();
      if (cmpDoc.exists) {
        const stats = cmpDoc.data()?.stats || {};
        await cmpRef.update({
          "stats.clicked": (stats.clicked || 0) + 1,
        });
      }

      await adminDb.collection("emailEvents").add({
        campaignId,
        recipientId: recipientId || null,
        event: "clicked",
        url: targetUrl,
        timestamp: new Date().toISOString(),
        userAgent: req.headers.get("user-agent") || null,
      });
    } catch (err) {
      console.warn("Track click error:", err);
    }
  }

  // Decode target URL and redirect immediately
  try {
    const decodedUrl = decodeURIComponent(targetUrl);
    return NextResponse.redirect(decodedUrl, 302);
  } catch {
    return NextResponse.redirect(targetUrl, 302);
  }
}
