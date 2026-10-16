import { NextRequest, NextResponse } from "next/server";
import { verifyServerAuth, unauthorizedResponse } from "@/lib/firebase/auth-middleware";
import { sendBatchEmails } from "@/lib/email/provider";
import { adminDb } from "@/lib/firebase/admin";
import { isValidEmail } from "@/lib/utils";

export async function POST(req: NextRequest) {
  try {
    const user = await verifyServerAuth(req);
    if (!user) {
      return unauthorizedResponse();
    }

    const body = await req.json();
    const {
      campaignId,
      name,
      subject,
      htmlContent,
      textContent,
      fromName,
      fromEmail,
      replyTo,
      recipients,
      idempotencyKey,
      trackOpens,
      trackClicks,
      smtpConfig,
    } = body;

    if (!campaignId || !subject || !htmlContent || !Array.isArray(recipients) || recipients.length === 0) {
      return NextResponse.json(
        { error: "Missing required campaign data or empty recipient list" },
        { status: 400 }
      );
    }

    // Filter valid email addresses and deduplicate
    const uniqueRecipients = new Map<string, any>();
    for (const r of recipients) {
      const email = (r.email || "").trim().toLowerCase();
      if (isValidEmail(email) && !uniqueRecipients.has(email)) {
        uniqueRecipients.set(email, {
          recipientId: r.id || `rcp_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
          email,
          firstName: r.firstName || "",
          lastName: r.lastName || "",
          company: r.company || "",
          customFields: r.customFields || {},
        });
      }
    }

    const validRecipientList = Array.from(uniqueRecipients.values());

    if (validRecipientList.length === 0) {
      return NextResponse.json(
        { error: "No valid email addresses found in the recipient list" },
        { status: 400 }
      );
    }

    // Server-side suppression check: Exclude any emails that are suppressed/unsubscribed
    const suppressedEmails = new Set<string>();
    if (adminDb) {
      try {
        const suppressionSnap = await adminDb
          .collection("suppressionLists")
          .where("userId", "==", user.uid)
          .get();
        suppressionSnap.forEach((doc) => {
          const data = doc.data();
          if (data.email) suppressedEmails.add(data.email.toLowerCase());
        });
      } catch (err) {
        console.warn("Server suppression check warning:", err);
      }
    }

    const filteredRecipients = validRecipientList.filter(
      (r) => !suppressedEmails.has(r.email)
    );

    const suppressedCount = validRecipientList.length - filteredRecipients.length;

    if (filteredRecipients.length === 0) {
      return NextResponse.json(
        {
          error: "All selected recipients are in the suppression or unsubscribe list.",
          suppressedCount,
        },
        { status: 400 }
      );
    }

    // Execute server-side batch send with throttling & exponential backoff
    const batchResult = await sendBatchEmails(
      filteredRecipients,
      {
        id: campaignId,
        subject,
        htmlContent,
        textContent,
        fromName: fromName || "MailForge",
        fromEmail: fromEmail || smtpConfig?.user || user.email || "",
        replyTo,
        trackOpens: trackOpens !== false,
        trackClicks: trackClicks !== false,
        smtpConfig,
      },
      undefined,
      { batchSize: 30, delayBetweenBatchesMs: 200 }
    );

    const status =
      batchResult.stats.failed === 0
        ? "completed"
        : batchResult.stats.sent > 0
        ? "completed_with_errors"
        : "failed";

    // Update Firestore if Admin SDK is connected
    if (adminDb) {
      try {
        const campaignRef = adminDb.collection("campaigns").doc(campaignId);
        await campaignRef.set(
          {
            userId: user.uid,
            name: name || "Bulk Campaign",
            subject,
            fromName: fromName || "MailForge",
            fromEmail: fromEmail || smtpConfig?.user || user.email || "",
            replyTo: replyTo || "",
            htmlContent,
            textContent: textContent || "",
            recipientCount: validRecipientList.length,
            status,
            idempotencyKey: idempotencyKey || null,
            stats: {
              total: validRecipientList.length,
              sent: batchResult.stats.sent,
              delivered: batchResult.stats.sent,
              bounced: 0,
              failed: batchResult.stats.failed,
              unsubscribed: suppressedCount,
              opened: 0,
              clicked: 0,
            },
            completedAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          },
          { merge: true }
        );

        // Store recipient records in batch
        const batch = adminDb.batch();
        for (const res of batchResult.results) {
          const rcpRef = adminDb.collection("campaignRecipients").doc(res.recipientId);
          batch.set(rcpRef, {
            campaignId,
            userId: user.uid,
            email: res.email,
            status: res.success ? "sent" : "failed",
            providerMessageId: res.providerMessageId || null,
            error: res.error || null,
            sentAt: res.success ? new Date().toISOString() : null,
          });
        }
        await batch.commit();
      } catch (dbErr) {
        console.error("Firestore batch record update error:", dbErr);
      }
    }

    return NextResponse.json({
      success: true,
      campaignId,
      status,
      stats: {
        total: validRecipientList.length,
        sent: batchResult.stats.sent,
        failed: batchResult.stats.failed,
        suppressed: suppressedCount,
      },
      results: batchResult.results,
    });
  } catch (err: any) {
    console.error("Campaign send handler error:", err);
    return NextResponse.json(
      { error: err?.message || "Internal server error while dispatching campaign" },
      { status: 500 }
    );
  }
}
