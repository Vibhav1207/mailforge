import { NextRequest, NextResponse } from "next/server";
import { verifyServerAuth, unauthorizedResponse } from "@/lib/firebase/auth-middleware";
import { sendEmailWithRetry } from "@/lib/email/provider";
import { adminDb } from "@/lib/firebase/admin";

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const user = await verifyServerAuth(req);
    if (!user) return unauthorizedResponse();

    const { id: campaignId } = await params;
    const body = await req.json().catch(() => ({}));
    const failedList: Array<{ recipientId: string; email: string; firstName?: string; lastName?: string; company?: string }> =
      body.failedRecipients || [];

    // Verify campaign ownership if DB is available
    let campaignData: any = null;
    if (adminDb) {
      const snap = await adminDb.collection("campaigns").doc(campaignId).get();
      if (snap.exists) {
        campaignData = snap.data();
        if (campaignData.userId !== user.uid) {
          return NextResponse.json({ error: "Unauthorized access to campaign" }, { status: 403 });
        }
      }
    }

    if (!campaignData && body.campaign) {
      campaignData = body.campaign;
    }

    if (!campaignData) {
      return NextResponse.json({ error: "Campaign not found" }, { status: 404 });
    }

    if (failedList.length === 0) {
      return NextResponse.json({ error: "No failed recipients provided for retry" }, { status: 400 });
    }

    let retrySuccessCount = 0;
    let retryFailCount = 0;
    const retryResults: any[] = [];

    for (const r of failedList) {
      const res = await sendEmailWithRetry({
        to: r.email,
        subject: campaignData.subject,
        html: campaignData.htmlContent,
        text: campaignData.textContent,
        fromName: campaignData.fromName,
        fromEmail: campaignData.fromEmail,
        replyTo: campaignData.replyTo,
        campaignId,
        recipientId: r.recipientId,
        variables: {
          firstName: r.firstName,
          lastName: r.lastName,
          company: r.company,
        },
      });

      if (res.success) {
        retrySuccessCount++;
      } else {
        retryFailCount++;
      }

      retryResults.push({
        recipientId: r.recipientId,
        email: r.email,
        success: res.success,
        providerMessageId: res.providerMessageId,
        error: res.error,
      });

      // Update recipient record
      if (adminDb) {
        try {
          await adminDb.collection("campaignRecipients").doc(r.recipientId).set(
            {
              status: res.success ? "sent" : "failed",
              providerMessageId: res.providerMessageId || null,
              error: res.error || null,
              sentAt: res.success ? new Date().toISOString() : null,
            },
            { merge: true }
          );
        } catch (e) {
          console.warn("Recipient status update error:", e);
        }
      }
    }

    // Update campaign stats
    if (adminDb && campaignData.stats) {
      try {
        const newSent = (campaignData.stats.sent || 0) + retrySuccessCount;
        const newFailed = Math.max(0, (campaignData.stats.failed || 0) - retrySuccessCount);
        await adminDb.collection("campaigns").doc(campaignId).update({
          "stats.sent": newSent,
          "stats.failed": newFailed,
          status: newFailed === 0 ? "completed" : "completed_with_errors",
          updatedAt: new Date().toISOString(),
        });
      } catch (e) {
        console.warn("Campaign retry stat update warning:", e);
      }
    }

    return NextResponse.json({
      success: true,
      retriedTotal: failedList.length,
      retriedSuccess: retrySuccessCount,
      retriedFailed: retryFailCount,
      results: retryResults,
    });
  } catch (err: any) {
    console.error("Retry endpoint error:", err);
    return NextResponse.json({ error: err.message || "Failed to retry campaign" }, { status: 500 });
  }
}
