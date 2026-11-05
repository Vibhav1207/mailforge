import { createHash } from "node:crypto";
import { getAdminDb, isFirebaseAdminConfigured } from "@/lib/firebase/admin";
import { getMongoDb, isMongoConfigured } from "@/lib/mongodb";

export function suppressionId(userId: string, email: string): string {
  return createHash("sha256").update(JSON.stringify([userId, email.trim().toLowerCase()])).digest("hex");
}

export async function suppressedAddresses(userId: string): Promise<Set<string>> {
  if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
    const db = await getMongoDb();
    const [suppressions, contacts] = await Promise.all([
      db.collection("suppressionLists").find({ userId }).toArray(),
      db.collection("contacts").find({ userId }).toArray(),
    ]);
    const emails = new Set<string>();
    for (const doc of suppressions) {
      if (typeof (doc as any).email === "string") emails.add((doc as any).email.trim().toLowerCase());
    }
    for (const doc of contacts) {
      if ((doc as any).status !== "active" && typeof (doc as any).email === "string") emails.add((doc as any).email.trim().toLowerCase());
    }
    return emails;
  }

  const db = getAdminDb();
  // Include legacy records and contact statuses; any lookup failure stops dispatch.
  const [suppressions, contacts] = await Promise.all([
    db.collection("suppressionLists").where("userId", "==", userId).get(),
    db.collection("contacts").where("userId", "==", userId).get(),
  ]);
  const emails = new Set<string>();
  for (const doc of suppressions.docs) {
    if (typeof doc.data().email === "string") emails.add(doc.data().email.trim().toLowerCase());
  }
  for (const doc of contacts.docs) {
    if (doc.data().status !== "active" && typeof doc.data().email === "string") emails.add(doc.data().email.trim().toLowerCase());
  }
  return emails;
}
