import { NextRequest, NextResponse } from "next/server";
import { adminDb } from "@/lib/firebase/admin";
import { isValidEmail } from "@/lib/utils";

export async function POST(req: NextRequest) {
  try {
    const { email, campaignId, reason } = await req.json();

    if (!email || !isValidEmail(email)) {
      return NextResponse.json({ error: "Invalid email address" }, { status: 400 });
    }

    const cleanEmail = email.trim().toLowerCase();

    // If Admin DB is available, update contacts and suppression list
    if (adminDb) {
      // Find contacts with this email and mark unsubscribed
      const contactsSnap = await adminDb
        .collection("contacts")
        .where("email", "==", cleanEmail)
        .get();

      const batch = adminDb.batch();
      contactsSnap.forEach((doc) => {
        batch.update(doc.ref, {
          status: "unsubscribed",
          suppressionReason: reason || "User clicked unsubscribe",
          updatedAt: new Date().toISOString(),
        });
      });

      // Add to suppression lists
      const supRef = adminDb.collection("suppressionLists").doc();
      batch.set(supRef, {
        email: cleanEmail,
        campaignId: campaignId || null,
        reason: "unsubscribe",
        note: reason || "Direct unsubscribe request",
        createdAt: new Date().toISOString(),
      });

      await batch.commit();
    }

    return NextResponse.json({
      success: true,
      message: `${cleanEmail} has been successfully unsubscribed.`,
    });
  } catch (err: any) {
    console.error("Unsubscribe API error:", err);
    return NextResponse.json({ error: "Failed to process unsubscribe" }, { status: 500 });
  }
}
