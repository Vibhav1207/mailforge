import { FieldValue } from "firebase-admin/firestore";
import { getAdminDb } from "@/lib/firebase/admin";
import type { EmailLink } from "@/lib/email/links";

export async function recordTracking(link: EmailLink): Promise<void> {
  const db = getAdminDb();
  const recipientRef = db.collection("campaignRecipients").doc(link.recipientId);
  const campaignRef = db.collection("campaigns").doc(link.campaignId);
  await db.runTransaction(async (tx) => {
    const [recipient, campaign] = await Promise.all([tx.get(recipientRef), tx.get(campaignRef)]);
    const data = recipient.data();
    if (!data || !campaign.exists || data.userId !== link.userId || campaign.data()?.userId !== link.userId || data.campaignId !== link.campaignId || data.email !== link.email) return;
    const click = link.purpose === "click";
    if (click ? campaign.data()?.trackClicks === false : campaign.data()?.trackOpens === false) return;
    const timestamp = click ? "clickedAt" : "openedAt";
    const count = click ? "clickCount" : "openCount";
    const now = new Date().toISOString();
    tx.update(recipientRef, { [count]: FieldValue.increment(1), [timestamp]: data[timestamp] || now });
    // Campaign metrics count unique recipients; repeated pixel loads are not new opens.
    if (!data[timestamp]) {
      tx.update(campaignRef, { [click ? "stats.clicked" : "stats.opened"]: FieldValue.increment(1) });
      tx.create(db.collection("emailEvents").doc(), { userId: link.userId, campaignId: link.campaignId, recipientId: link.recipientId, email: link.email, event: click ? "clicked" : "opened", timestamp: now, ...(click ? { url: link.url } : {}) });
    }
  });
}
