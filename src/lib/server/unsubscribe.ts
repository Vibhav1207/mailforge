import { FieldValue } from "firebase-admin/firestore";
import { getAdminDb } from "@/lib/firebase/admin";
import type { EmailLink } from "@/lib/email/links";
import { ApiError } from "./errors";
import { suppressionId } from "./suppression";

export async function unsubscribeRecipient(link: EmailLink): Promise<void> {
  const db = getAdminDb();
  const suppressionRef = db.collection("suppressionLists").doc(suppressionId(link.userId, link.email));
  const campaignRef = db.collection("campaigns").doc(link.campaignId);
  const recipientRef = db.collection("campaignRecipients").doc(link.recipientId);
  await db.runTransaction(async (tx) => {
    const [suppression, campaign, recipient, contacts] = await Promise.all([
      tx.get(suppressionRef), tx.get(campaignRef), tx.get(recipientRef),
      tx.get(db.collection("contacts").where("userId", "==", link.userId).where("email", "==", link.email).limit(400)),
    ]);
    if ((campaign.exists && campaign.data()?.userId !== link.userId) ||
        (recipient.exists && (recipient.data()?.userId !== link.userId || recipient.data()?.campaignId !== link.campaignId || recipient.data()?.email !== link.email))) {
      throw new ApiError(400, "This email link does not match its recipient.", "INVALID_EMAIL_LINK");
    }
    const now = new Date().toISOString();
    if (!suppression.exists) tx.create(suppressionRef, { userId: link.userId, email: link.email, reason: "unsubscribe", campaignId: link.campaignId, createdAt: now });
    for (const contact of contacts.docs) tx.update(contact.ref, { status: "unsubscribed", suppressionReason: "Recipient opted out", updatedAt: now });
    if (recipient.exists && !recipient.data()?.unsubscribedAt) {
      tx.update(recipientRef, { unsubscribedAt: now });
      if (campaign.exists) tx.update(campaignRef, { "stats.unsubscribed": FieldValue.increment(1) });
    }
  });
}
