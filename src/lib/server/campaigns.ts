import { createHash, randomUUID } from "node:crypto";
import { FieldValue } from "firebase-admin/firestore";
import { z } from "zod";
import { getAdminDb, isFirebaseAdminConfigured } from "@/lib/firebase/admin";
import { getMongoDb, isMongoConfigured } from "@/lib/mongodb";
import type { AuthenticatedUser } from "@/lib/firebase/auth-middleware";
import type { Campaign, CampaignRecipient } from "@/types";
import { sendSingleEmail } from "@/lib/email/provider";
import { createSmtpTransport } from "@/lib/email/smtp";
import { appUrl, integerSetting, signingSecret } from "./config";
import { ApiError } from "./errors";
import { getOwned } from "./data";
import { resolveSmtp, stripUndefined } from "./settings";
import { suppressedAddresses, suppressionId } from "./suppression";
import { sendCampaignSchema } from "./validation";
import { buildSafeOwnershipFilter } from "./mongodb-security";

type SendInput = z.infer<typeof sendCampaignSchema>;
type RecipientInput = SendInput["recipients"][number];
interface CampaignJob {
  userId: string;
  userEmail: string;
  campaignId: string;
  recipients: RecipientInput[];
  cursor: number;
  state: "ready" | "running" | "done" | "cancelled";
  nextRunAt: number;
  leaseOwner?: string | null;
  leaseUntil?: number;
  activeRecipientId?: string | null;
}
const LEASE_MS = 120_000;

export function recipientId(campaignId: string, email: string): string {
  return createHash("sha256").update(JSON.stringify([campaignId, email.toLowerCase()])).digest("hex");
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, canonical(item)]));
  return value;
}

export async function enqueueCampaign(user: AuthenticatedUser, input: SendInput) {
  const now = Date.now();
  const scheduledAt = input.scheduledFor ? Date.parse(input.scheduledFor) : now;
  const unique = new Map<string, RecipientInput>();
  for (const { id: _id, ...recipient } of input.recipients) if (!unique.has(recipient.email)) unique.set(recipient.email, recipient);
  const recipients = Array.from(unique.values()).sort((a, b) => a.email.localeCompare(b.email));
  const { recipients: _recipients, idempotencyKey, smtpConfig, ...content } = input;
  const fingerprint = createHash("sha256").update(JSON.stringify(canonical({ ...content, recipients }))).digest("hex");

  if (input.scheduledFor && scheduledAt <= now) throw new ApiError(400, "Choose a scheduling time in the future.", "INVALID_SCHEDULE");
  appUrl();
  signingSecret();
  const smtp = await resolveSmtp(user, smtpConfig);
  const fromEmail = input.fromEmail || (smtp.host === "smtp.gmail.com" ? smtp.user : process.env.FROM_EMAIL || user.email);
  if (smtp.host === "smtp.gmail.com" && fromEmail.toLowerCase() !== smtp.user.toLowerCase()) {
    throw new ApiError(400, "For Gmail, the From address must match the connected Gmail account.", "INVALID_SENDER");
  }
  const timestamp = new Date(now).toISOString();
  const campaign: Campaign = stripUndefined({
    ...content,
    id: input.campaignId,
    userId: user.uid,
    fromEmail,
    recipientCount: recipients.length,
    status: input.scheduledFor ? "scheduled" : "queued",
    idempotencyKey,
    stats: { total: recipients.length, sent: 0, delivered: 0, failed: 0, bounced: 0, unsubscribed: 0, suppressed: 0, opened: 0, clicked: 0 },
    createdAt: timestamp,
    updatedAt: timestamp,
    completedAt: null,
  });
  const job: CampaignJob = {
    userId: user.uid,
    userEmail: user.email,
    campaignId: input.campaignId,
    recipients,
    cursor: 0,
    state: "ready",
    nextRunAt: scheduledAt,
  };
  if (Buffer.byteLength(JSON.stringify(job)) > 2_500_000) {
    throw new ApiError(413, "This recipient data is too large. Split the campaign into smaller groups.", "PAYLOAD_TOO_LARGE");
  }

  // --- MONGODB IMPLEMENTATION ---
  if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
    const db = await getMongoDb();
    const key = createHash("sha256").update(JSON.stringify([user.uid, idempotencyKey])).digest("hex");
    const priorKey = await db.collection("idempotencyKeys").findOne({ _id: key as any });
    if (priorKey) {
      if ((priorKey as any).fingerprint !== fingerprint) {
        throw new ApiError(409, "This send key was already used for different campaign data.", "IDEMPOTENCY_CONFLICT");
      }
      return { campaign: (await getOwned("campaigns", (priorKey as any).campaignId, user.uid)) as Campaign, replayed: true };
    }

    const existingCamp = await db.collection("campaigns").findOne(buildSafeOwnershipFilter(input.campaignId, user.uid));
    if (existingCamp && (existingCamp as any).userId !== user.uid) throw new ApiError(404, "Campaign not found.", "NOT_FOUND");
    if (existingCamp && (existingCamp as any).status !== "draft") throw new ApiError(409, "This campaign has already been queued. Open its report or duplicate it to send again.", "CAMPAIGN_ALREADY_QUEUED");

    campaign.createdAt = (existingCamp as any)?.createdAt || timestamp;

    await Promise.all([
      db.collection("campaigns").updateOne(
        { _id: input.campaignId as any },
        { $set: campaign },
        { upsert: true }
      ),
      db.collection("campaignJobs").updateOne(
        { _id: input.campaignId as any },
        { $set: stripUndefined(job) },
        { upsert: true }
      ),
      db.collection("idempotencyKeys").updateOne(
        { _id: key as any },
        { $set: { userId: user.uid, campaignId: campaign.id, fingerprint, createdAt: timestamp } },
        { upsert: true }
      ),
    ]);

    return { campaign, replayed: false };
  }

  // --- FIRESTORE IMPLEMENTATION ---
  const db = getAdminDb();
  const cmpRef = db.collection("campaigns").doc(input.campaignId);
  const jobRef = db.collection("campaignJobs").doc(input.campaignId);
  const key = createHash("sha256").update(JSON.stringify([user.uid, idempotencyKey])).digest("hex");
  const keyRef = db.collection("idempotencyKeys").doc(key);

  const prior = await keyRef.get();
  if (prior.exists) {
    if (prior.data()?.fingerprint !== fingerprint) throw new ApiError(409, "This send key was already used for different campaign data.", "IDEMPOTENCY_CONFLICT");
    return { campaign: await getOwned("campaigns", prior.data()!.campaignId, user.uid) as Campaign, replayed: true };
  }

  return db.runTransaction(async (tx) => {
    const [existing, existingKey] = await Promise.all([tx.get(cmpRef), tx.get(keyRef)]);
    if (existingKey.exists) {
      if (existingKey.data()?.fingerprint !== fingerprint) throw new ApiError(409, "This send key was already used for different campaign data.", "IDEMPOTENCY_CONFLICT");
      if (!existing.exists || existing.data()?.userId !== user.uid) throw new ApiError(409, "The original campaign is no longer available.", "CAMPAIGN_UNAVAILABLE");
      return { campaign: { ...existing.data(), id: existing.id } as Campaign, replayed: true };
    }
    if (existing.exists && existing.data()?.userId !== user.uid) throw new ApiError(404, "Campaign not found.", "NOT_FOUND");
    if (existing.exists && existing.data()?.status !== "draft") throw new ApiError(409, "This campaign has already been queued. Open its report or duplicate it to send again.", "CAMPAIGN_ALREADY_QUEUED");
    campaign.createdAt = existing.data()?.createdAt || timestamp;
    tx.set(cmpRef, campaign);
    tx.set(jobRef, stripUndefined(job));
    tx.create(keyRef, { userId: user.uid, campaignId: campaign.id, fingerprint, createdAt: timestamp });
    return { campaign, replayed: false };
  });
}

export async function campaignRecipients(userId: string, campaignId: string): Promise<CampaignRecipient[]> {
  await getOwned("campaigns", campaignId, userId);

  if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
    const db = await getMongoDb();
    const [jobDoc, storedDocs] = await Promise.all([
      db.collection("campaignJobs").findOne({ _id: campaignId as any }),
      db.collection("campaignRecipients").find({ campaignId, userId }).toArray(),
    ]);

    const job = jobDoc as unknown as CampaignJob | null;
    const records = new Map<string, CampaignRecipient>();

    for (const recipient of job?.recipients || []) {
      const id = recipientId(campaignId, recipient.email);
      records.set(id, {
        ...recipient,
        id,
        userId,
        campaignId,
        status: job?.state === "cancelled" ? "cancelled" : "queued",
        attempts: 0,
      });
    }

    for (const doc of storedDocs) {
      const { _id, ...rest } = doc as any;
      records.set(_id?.toString() || rest.id, { ...rest, id: _id?.toString() || rest.id } as CampaignRecipient);
    }

    return Array.from(records.values());
  }

  const db = getAdminDb();
  const [jobSnap, stored] = await Promise.all([
    db.collection("campaignJobs").doc(campaignId).get(),
    db.collection("campaignRecipients").where("campaignId", "==", campaignId).get(),
  ]);
  const job = jobSnap.data() as CampaignJob | undefined;
  const records = new Map<string, CampaignRecipient>();
  for (const recipient of job?.recipients || []) {
    const id = recipientId(campaignId, recipient.email);
    records.set(id, { ...recipient, id, userId, campaignId, status: job?.state === "cancelled" ? "cancelled" : "queued", attempts: 0 });
  }
  for (const doc of stored.docs) if (doc.data().userId === userId) records.set(doc.id, { ...doc.data(), id: doc.id } as CampaignRecipient);
  return Array.from(records.values());
}

async function claimJob(campaignId: string): Promise<{ job: CampaignJob; owner: string } | null> {
  const owner = randomUUID();
  const now = Date.now();

  if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
    const db = await getMongoDb();
    const campaign = await db.collection("campaigns").findOne({ _id: campaignId as any });
    if (!campaign || campaign.status === "cancelled") return null;

    const job = (await db.collection("campaignJobs").findOne({ _id: campaignId as any })) as unknown as CampaignJob | null;
    if (!job || ["done", "cancelled"].includes(job.state) || job.nextRunAt > now || (job.leaseUntil || 0) > now) {
      return null;
    }

    if (job.activeRecipientId) {
      const recipient = await db.collection("campaignRecipients").findOne({ _id: job.activeRecipientId as any });
      if (recipient?.status === "sending") {
        await Promise.all([
          db.collection("campaignRecipients").updateOne(
            { _id: job.activeRecipientId as any },
            { $set: { status: "unknown", retryable: false, error: "Delivery was interrupted before confirmation. Check the mail provider before resending." } }
          ),
          db.collection("campaigns").updateOne(
            { _id: campaignId as any },
            { $inc: { "stats.failed": 1 } }
          ),
        ]);
      }
    }

    await Promise.all([
      db.collection("campaignJobs").updateOne(
        { _id: campaignId as any },
        { $set: { state: "running", leaseOwner: owner, leaseUntil: now + LEASE_MS, nextRunAt: now + LEASE_MS, activeRecipientId: null } }
      ),
      db.collection("campaigns").updateOne(
        { _id: campaignId as any },
        { $set: { status: "sending", updatedAt: new Date(now).toISOString() } }
      ),
    ]);

    return { job, owner };
  }

  const db = getAdminDb();
  const ref = db.collection("campaignJobs").doc(campaignId);
  const cmpRef = db.collection("campaigns").doc(campaignId);
  return db.runTransaction(async (tx) => {
    const [snap, campaign] = await Promise.all([tx.get(ref), tx.get(cmpRef)]);
    const job = snap.data() as CampaignJob | undefined;
    if (!job || !campaign.exists || ["done", "cancelled"].includes(job.state) || job.nextRunAt > now || (job.leaseUntil || 0) > now) return null;
    if (campaign.data()?.status === "cancelled") return null;
    if (job.activeRecipientId) {
      const recipientRef = db.collection("campaignRecipients").doc(job.activeRecipientId);
      const recipient = await tx.get(recipientRef);
      if (recipient.data()?.status === "sending") {
        tx.update(recipientRef, { status: "unknown", retryable: false, error: "Delivery was interrupted before confirmation. Check the mail provider before resending." });
        tx.update(cmpRef, { "stats.failed": FieldValue.increment(1) });
      }
    }
    tx.update(ref, { state: "running", leaseOwner: owner, leaseUntil: now + LEASE_MS, nextRunAt: now + LEASE_MS, activeRecipientId: null });
    tx.update(cmpRef, { status: "sending", updatedAt: new Date(now).toISOString() });
    return { job, owner };
  });
}

async function reserveRecipient(campaignId: string, owner: string, candidate: RecipientInput, isInitial: boolean, suppressed: Set<string>) {
  const id = recipientId(campaignId, candidate.email);

  if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
    const db = await getMongoDb();
    const job = (await db.collection("campaignJobs").findOne({ _id: campaignId as any })) as unknown as CampaignJob | null;
    if (!job || job.leaseOwner !== owner || job.state !== "running") return null;

    const [existing, suppression] = await Promise.all([
      db.collection("campaignRecipients").findOne({ _id: id as any }),
      db.collection("suppressionLists").findOne({ _id: suppressionId(job.userId, candidate.email) as any }),
    ]);

    if (existing && existing.status !== "queued") {
      if (isInitial) {
        await db.collection("campaignJobs").updateOne({ _id: campaignId as any }, { $inc: { cursor: 1 } });
      }
      return null;
    }
    if (!isInitial && existing?.nextAttemptAt && existing.nextAttemptAt > new Date().toISOString()) {
      return null;
    }

    const blocked = suppressed.has(candidate.email.toLowerCase()) || Boolean(suppression);
    const recipient = stripUndefined({
      ...candidate,
      id,
      campaignId,
      userId: job.userId,
      status: blocked ? "suppressed" : "sending",
      attempts: (existing?.attempts || 0) + (blocked ? 0 : 1),
      attemptOwner: owner,
      retryable: false,
      nextAttemptAt: null,
      ...(blocked ? { error: "Recipient has opted out or is suppressed." } : {}),
    });

    await Promise.all([
      db.collection("campaignRecipients").updateOne(
        { _id: id as any },
        { $set: recipient },
        { upsert: true }
      ),
      db.collection("campaignJobs").updateOne(
        { _id: campaignId as any },
        {
          $set: { activeRecipientId: blocked ? null : id, leaseUntil: Date.now() + LEASE_MS, nextRunAt: Date.now() + LEASE_MS },
          ...(isInitial ? { $inc: { cursor: 1 } } : {}),
        }
      ),
      blocked
        ? db.collection("campaigns").updateOne({ _id: campaignId as any }, { $inc: { "stats.suppressed": 1 } })
        : Promise.resolve(),
    ]);

    return blocked ? null : recipient;
  }

  const db = getAdminDb();
  const jobRef = db.collection("campaignJobs").doc(campaignId);
  const cmpRef = db.collection("campaigns").doc(campaignId);
  const ref = db.collection("campaignRecipients").doc(id);
  return db.runTransaction(async (tx) => {
    const jobSnap = await tx.get(jobRef);
    const job = jobSnap.data() as CampaignJob;
    if (job.leaseOwner !== owner || job.state !== "running") return null;
    const [existing, suppression] = await Promise.all([
      tx.get(ref), tx.get(db.collection("suppressionLists").doc(suppressionId(job.userId, candidate.email))),
    ]);
    if (existing.exists && existing.data()?.status !== "queued") {
      if (isInitial) tx.update(jobRef, { cursor: job.cursor + 1 });
      return null;
    }
    if (!isInitial && existing.data()?.nextAttemptAt > new Date().toISOString()) return null;
    const blocked = suppressed.has(candidate.email.toLowerCase()) || suppression.exists;
    const recipient = stripUndefined({
      ...candidate, id, campaignId, userId: job.userId, status: blocked ? "suppressed" : "sending",
      attempts: (existing.data()?.attempts || 0) + (blocked ? 0 : 1),
      attemptOwner: owner, retryable: false, nextAttemptAt: null,
      ...(blocked ? { error: "Recipient has opted out or is suppressed." } : {}),
    });
    tx.set(ref, recipient);
    tx.update(jobRef, { ...(isInitial ? { cursor: job.cursor + 1 } : {}), activeRecipientId: blocked ? null : id, leaseUntil: Date.now() + LEASE_MS, nextRunAt: Date.now() + LEASE_MS });
    if (blocked) tx.update(cmpRef, { "stats.suppressed": FieldValue.increment(1) });
    return blocked ? null : recipient;
  });
}

export async function processCampaign(campaignId: string, budgetMs = 45_000): Promise<void> {
  const claimed = await claimJob(campaignId);
  if (!claimed) return;
  const { owner } = claimed;
  const deadline = Date.now() + budgetMs;
  const isMongo = !isFirebaseAdminConfigured() && isMongoConfigured();
  let transport: Awaited<ReturnType<typeof createSmtpTransport>> | undefined;

  try {
    const user = { uid: claimed.job.userId, email: claimed.job.userEmail };
    const [smtp, suppressed] = await Promise.all([resolveSmtp(user), suppressedAddresses(user.uid)]);
    transport = await createSmtpTransport(smtp);

    let campaign: Campaign;
    if (isMongo) {
      const db = await getMongoDb();
      campaign = (await db.collection("campaigns").findOne({ _id: campaignId as any })) as unknown as Campaign;
    } else {
      const db = getAdminDb();
      campaign = (await db.collection("campaigns").doc(campaignId).get()).data() as Campaign;
    }

    while (Date.now() + 1500 < deadline) {
      let job: CampaignJob;
      let candidate: RecipientInput | undefined;
      let isInitial = false;

      if (isMongo) {
        const db = await getMongoDb();
        const jobDoc = await db.collection("campaignJobs").findOne({ _id: campaignId as any });
        job = jobDoc as unknown as CampaignJob;
        if (!job || job.leaseOwner !== owner || job.state !== "running") break;

        isInitial = job.cursor < job.recipients.length;
        candidate = isInitial ? job.recipients[job.cursor] : undefined;

        if (!candidate) {
          const queued = await db.collection("campaignRecipients")
            .find({ campaignId, status: "queued" })
            .sort({ nextAttemptAt: 1 })
            .limit(1)
            .toArray();
          const next = queued[0] as any;
          if (!next || (next.nextAttemptAt && next.nextAttemptAt > new Date().toISOString())) break;
          candidate = { email: next.email, name: next.name, firstName: next.firstName, lastName: next.lastName, company: next.company, customFields: next.customFields };
        }
      } else {
        const db = getAdminDb();
        const jobSnap = await db.collection("campaignJobs").doc(campaignId).get();
        job = jobSnap.data() as CampaignJob;
        if (!job || job.leaseOwner !== owner || job.state !== "running") break;

        isInitial = job.cursor < job.recipients.length;
        candidate = isInitial ? job.recipients[job.cursor] : undefined;

        if (!candidate) {
          const queued = await db.collection("campaignRecipients").where("campaignId", "==", campaignId).where("status", "==", "queued").orderBy("nextAttemptAt").limit(1).get();
          const next = queued.docs[0]?.data();
          if (!next || next.nextAttemptAt > new Date().toISOString()) break;
          candidate = { email: next.email, name: next.name, firstName: next.firstName, lastName: next.lastName, company: next.company, customFields: next.customFields };
        }
      }

      const recipient = await reserveRecipient(campaignId, owner, candidate, isInitial, suppressed);
      if (!recipient) continue;

      // Dispatch single email with rich personalization
      const result = await sendSingleEmail({
        to: recipient.email,
        fromEmail: campaign.fromEmail,
        fromName: campaign.fromName,
        subject: campaign.subject,
        html: campaign.htmlContent,
        text: campaign.textContent,
        replyTo: campaign.replyTo,
        userId: user.uid,
        campaignId,
        recipientId: recipient.id,
        trackOpens: campaign.trackOpens,
        trackClicks: campaign.trackClicks,
        smtpConfig: smtp,
        transport,
        variables: {
          ...recipient.customFields,
          name: recipient.name || [recipient.firstName, recipient.lastName].filter(Boolean).join(" "),
          firstName: recipient.firstName,
          lastName: recipient.lastName,
          company: recipient.company,
          email: recipient.email,
        },
      });

      const retry = !result.success && result.isTransient && !result.ambiguous && recipient.attempts < integerSetting("MAX_SEND_ATTEMPTS", 3, 1, 5);
      const now = new Date().toISOString();

      if (isMongo) {
        const db = await getMongoDb();
        await Promise.all([
          db.collection("campaignRecipients").updateOne(
            { _id: recipient.id as any },
            {
              $set: {
                status: result.success ? "sent" : result.ambiguous ? "unknown" : retry ? "queued" : "failed",
                providerMessageId: result.providerMessageId || null,
                error: result.error || null,
                retryable: Boolean(result.isTransient && !result.ambiguous),
                sentAt: result.success ? now : null,
                nextAttemptAt: retry ? new Date(Date.now() + 30_000 * 2 ** (recipient.attempts - 1)).toISOString() : null,
              },
            }
          ),
          db.collection("campaigns").updateOne(
            { _id: campaignId as any },
            {
              $inc: {
                ...(result.success ? { "stats.sent": 1 } : !retry ? { "stats.failed": 1 } : {}),
              },
            }
          ),
          db.collection("campaignJobs").updateOne(
            { _id: campaignId as any },
            { $set: { activeRecipientId: null } }
          ),
          db.collection("emailEvents").insertOne({
            campaignId,
            recipientId: recipient.id,
            userId: user.uid,
            email: recipient.email,
            event: result.success ? "sent" : "failed",
            timestamp: now,
            attempt: recipient.attempts,
            providerMessageId: result.providerMessageId || null,
          }),
        ]);
      } else {
        const db = getAdminDb();
        const ref = db.collection("campaignRecipients").doc(recipient.id);
        const jobRef = db.collection("campaignJobs").doc(campaignId);
        const cmpRef = db.collection("campaigns").doc(campaignId);

        await db.runTransaction(async (tx) => {
          const [latest, latestJob] = await Promise.all([tx.get(ref), tx.get(jobRef)]);
          if (latest.data()?.attemptOwner !== owner || latest.data()?.status !== "sending") return;

          tx.update(ref, {
            status: result.success ? "sent" : result.ambiguous ? "unknown" : retry ? "queued" : "failed",
            providerMessageId: result.providerMessageId || null,
            error: result.error || null,
            retryable: Boolean(result.isTransient && !result.ambiguous),
            sentAt: result.success ? now : null,
            nextAttemptAt: retry ? new Date(Date.now() + 30_000 * 2 ** (recipient.attempts - 1)).toISOString() : null,
          });
          if (result.success) tx.update(cmpRef, { "stats.sent": FieldValue.increment(1) });
          else if (!retry) tx.update(cmpRef, { "stats.failed": FieldValue.increment(1) });
          if (latestJob.data()?.leaseOwner === owner) tx.update(jobRef, { activeRecipientId: null });
          tx.create(db.collection("emailEvents").doc(), {
            campaignId,
            recipientId: recipient.id,
            userId: user.uid,
            email: recipient.email,
            event: result.success ? "sent" : "failed",
            timestamp: now,
            attempt: recipient.attempts,
            providerMessageId: result.providerMessageId || null,
          });
        });
      }

      const delay = integerSetting("BATCH_DELAY_MS", 2_000, 2_000, 10_000);
      if (delay && Date.now() + delay < deadline) {
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }

    // Finalize state after execution window
    if (isMongo) {
      const db = await getMongoDb();
      const [finalJobDoc, pendingDoc, finalCampDoc] = await Promise.all([
        db.collection("campaignJobs").findOne({ _id: campaignId as any }),
        db.collection("campaignRecipients").findOne({ campaignId, status: "queued" }),
        db.collection("campaigns").findOne({ _id: campaignId as any }),
      ]);
      const finalJob = finalJobDoc as unknown as CampaignJob;
      if (finalJob && finalJob.leaseOwner === owner && finalJob.state === "running") {
        const moreInitial = finalJob.cursor < finalJob.recipients.length;
        const finished = !moreInitial && !pendingDoc;
        const stats = (finalCampDoc as any)?.stats || { failed: 0, sent: 0 };
        const nextRunAt = moreInitial
          ? Date.now()
          : !pendingDoc
          ? Date.now()
          : Date.parse((pendingDoc as any).nextAttemptAt || new Date().toISOString());

        await Promise.all([
          db.collection("campaignJobs").updateOne(
            { _id: campaignId as any },
            { $set: { state: finished ? "done" : "ready", nextRunAt, leaseOwner: null, leaseUntil: 0, activeRecipientId: null } }
          ),
          db.collection("campaigns").updateOne(
            { _id: campaignId as any },
            {
              $set: {
                status: finished ? (stats.failed ? (stats.sent ? "completed_with_errors" : "failed") : "completed") : "queued",
                completedAt: finished ? new Date().toISOString() : null,
                updatedAt: new Date().toISOString(),
                errorMessage: null,
              },
            }
          ),
        ]);
      }
    } else {
      const db = getAdminDb();
      const jobRef = db.collection("campaignJobs").doc(campaignId);
      const cmpRef = db.collection("campaigns").doc(campaignId);
      const pending = await db.collection("campaignRecipients").where("campaignId", "==", campaignId).where("status", "==", "queued").orderBy("nextAttemptAt").limit(1).get();

      await db.runTransaction(async (tx) => {
        const [snap, campaignSnap] = await Promise.all([tx.get(jobRef), tx.get(cmpRef)]);
        const job = snap.data() as CampaignJob;
        if (job.leaseOwner !== owner || job.state !== "running") return;
        const moreInitial = job.cursor < job.recipients.length;
        const finished = !moreInitial && pending.empty;
        const stats = campaignSnap.data()!.stats;
        const nextRunAt = moreInitial ? Date.now() : pending.empty ? Date.now() : Date.parse(pending.docs[0].data().nextAttemptAt);
        tx.update(jobRef, { state: finished ? "done" : "ready", nextRunAt, leaseOwner: null, leaseUntil: 0, activeRecipientId: null });
        tx.update(cmpRef, {
          status: finished ? (stats.failed ? (stats.sent ? "completed_with_errors" : "failed") : "completed") : "queued",
          completedAt: finished ? new Date().toISOString() : null,
          updatedAt: new Date().toISOString(),
          errorMessage: null,
        });
      });
    }
  } catch (error) {
    if (isMongo) {
      const db = await getMongoDb();
      const job = (await db.collection("campaignJobs").findOne({ _id: campaignId as any })) as unknown as CampaignJob;
      if (job && job.leaseOwner === owner && job.state !== "cancelled") {
        await Promise.all([
          db.collection("campaigns").updateOne(
            { _id: campaignId as any },
            { $set: { errorMessage: error instanceof ApiError ? error.message : "Processing was interrupted. The worker will resume this campaign.", updatedAt: new Date().toISOString() } }
          ),
          !job.activeRecipientId
            ? db.collection("campaignJobs").updateOne(
                { _id: campaignId as any },
                { $set: { state: "ready", leaseOwner: null, leaseUntil: 0, nextRunAt: Date.now() + 60_000 } }
              )
            : Promise.resolve(),
        ]);
      }
    } else {
      const db = getAdminDb();
      const jobRef = db.collection("campaignJobs").doc(campaignId);
      const cmpRef = db.collection("campaigns").doc(campaignId);
      await db.runTransaction(async (tx) => {
        const latest = await tx.get(jobRef);
        if (latest.data()?.leaseOwner !== owner || latest.data()?.state === "cancelled") return;
        tx.update(cmpRef, { errorMessage: error instanceof ApiError ? error.message : "Processing was interrupted. The worker will resume this campaign.", updatedAt: new Date().toISOString() });
        if (!latest.data()?.activeRecipientId) tx.update(jobRef, { state: "ready", leaseOwner: null, leaseUntil: 0, nextRunAt: Date.now() + 60_000 });
      });
    }
    throw error;
  } finally {
    transport?.close();
  }
}

export async function retryCampaign(userId: string, campaignId: string) {
  await getOwned("campaigns", campaignId, userId);

  if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
    const db = await getMongoDb();
    const [jobDoc, failedDocs] = await Promise.all([
      db.collection("campaignJobs").findOne({ _id: campaignId as any }),
      db.collection("campaignRecipients").find({ campaignId, userId, status: "failed", retryable: true }).limit(400).toArray(),
    ]);
    const job = jobDoc as unknown as CampaignJob;
    if (!job) throw new ApiError(404, "Campaign job not found.", "NOT_FOUND");
    if (job.state !== "done") throw new ApiError(409, "Wait for the active campaign to finish before retrying.", "CAMPAIGN_ACTIVE");
    if (!failedDocs.length) throw new ApiError(400, "No transient failures are eligible for retry.", "NO_RETRYABLE_RECIPIENTS");

    const failedIds = failedDocs.map((d: any) => d._id);
    await Promise.all([
      db.collection("campaignRecipients").updateMany(
        { _id: { $in: failedIds } },
        { $set: { status: "queued", nextAttemptAt: new Date().toISOString(), error: null } }
      ),
      db.collection("campaigns").updateOne(
        { _id: campaignId as any },
        { $set: { status: "queued", completedAt: null, updatedAt: new Date().toISOString() }, $inc: { "stats.failed": -failedDocs.length } }
      ),
      db.collection("campaignJobs").updateOne(
        { _id: campaignId as any },
        { $set: { state: "ready", nextRunAt: Date.now(), leaseUntil: 0, leaseOwner: null, activeRecipientId: null } }
      ),
    ]);

    return failedDocs.length;
  }

  const db = getAdminDb();
  const jobRef = db.collection("campaignJobs").doc(campaignId);
  const cmpRef = db.collection("campaigns").doc(campaignId);
  return db.runTransaction(async (tx) => {
    const [job, campaign, failed] = await Promise.all([
      tx.get(jobRef), tx.get(cmpRef),
      tx.get(db.collection("campaignRecipients").where("campaignId", "==", campaignId).where("status", "==", "failed").limit(400)),
    ]);
    if (!job.exists || campaign.data()?.userId !== userId) throw new ApiError(404, "Campaign job not found.", "NOT_FOUND");
    if (job.data()?.state !== "done") throw new ApiError(409, "Wait for the active campaign to finish before retrying.", "CAMPAIGN_ACTIVE");
    const eligible = failed.docs.filter((doc) => doc.data().userId === userId && doc.data().retryable === true);
    if (!eligible.length) throw new ApiError(400, "No transient failures are eligible for retry. Permanent and uncertain deliveries are not resent.", "NO_RETRYABLE_RECIPIENTS");
    for (const doc of eligible) tx.update(doc.ref, { status: "queued", nextAttemptAt: new Date().toISOString(), error: null });
    tx.update(cmpRef, { status: "queued", "stats.failed": FieldValue.increment(-eligible.length), completedAt: null, updatedAt: new Date().toISOString() });
    tx.update(jobRef, { state: "ready", nextRunAt: Date.now(), leaseUntil: 0, leaseOwner: null, activeRecipientId: null });
    return eligible.length;
  });
}

export async function resumeCampaign(userId: string, campaignId: string): Promise<void> {
  await getOwned("campaigns", campaignId, userId);
  const now = Date.now();
  const timestamp = new Date(now).toISOString();

  if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
    const db = await getMongoDb();
    const [jobDoc, campaignDoc] = await Promise.all([
      db.collection("campaignJobs").findOne({ _id: campaignId as any }),
      db.collection("campaigns").findOne({ _id: campaignId as any }),
    ]);
    const job = jobDoc as unknown as CampaignJob | null;
    const campaign = campaignDoc as any;
    if (!job || !campaign || campaign.userId !== userId) throw new ApiError(404, "Campaign job not found.", "NOT_FOUND");
    if (["done", "cancelled"].includes(job.state) || ["completed", "completed_with_errors", "failed", "cancelled"].includes(campaign.status)) {
      throw new ApiError(409, "This campaign has no queued work to resume.", "CAMPAIGN_NOT_RESUMABLE");
    }

    const updates: Promise<unknown>[] = [];
    if (job.activeRecipientId) {
      const active = await db.collection("campaignRecipients").findOne({ _id: job.activeRecipientId as any });
      if (active?.status === "sending") {
        updates.push(
          db.collection("campaignRecipients").updateOne(
            { _id: job.activeRecipientId as any },
            { $set: { status: "unknown", retryable: false, error: "Delivery was interrupted before confirmation. This recipient was not resent." } },
          ),
          db.collection("campaigns").updateOne({ _id: campaignId as any }, { $inc: { "stats.failed": 1 } }),
        );
      }
    }
    updates.push(
      db.collection("campaignJobs").updateOne(
        { _id: campaignId as any },
        { $set: { state: "ready", nextRunAt: now, leaseOwner: null, leaseUntil: 0, activeRecipientId: null } },
      ),
      db.collection("campaigns").updateOne(
        { _id: campaignId as any },
        { $set: { status: "queued", completedAt: null, errorMessage: null, updatedAt: timestamp } },
      ),
    );
    await Promise.all(updates);
    return;
  }

  const db = getAdminDb();
  const jobRef = db.collection("campaignJobs").doc(campaignId);
  const cmpRef = db.collection("campaigns").doc(campaignId);
  await db.runTransaction(async (tx) => {
    const [jobSnap, campaignSnap] = await Promise.all([tx.get(jobRef), tx.get(cmpRef)]);
    const job = jobSnap.data() as CampaignJob | undefined;
    const campaign = campaignSnap.data();
    if (!job || !campaign || campaign.userId !== userId) throw new ApiError(404, "Campaign job not found.", "NOT_FOUND");
    if (["done", "cancelled"].includes(job.state) || ["completed", "completed_with_errors", "failed", "cancelled"].includes(campaign.status)) {
      throw new ApiError(409, "This campaign has no queued work to resume.", "CAMPAIGN_NOT_RESUMABLE");
    }
    if (job.activeRecipientId) {
      const recipientRef = db.collection("campaignRecipients").doc(job.activeRecipientId);
      const recipient = await tx.get(recipientRef);
      if (recipient.data()?.status === "sending") {
        tx.update(recipientRef, { status: "unknown", retryable: false, error: "Delivery was interrupted before confirmation. This recipient was not resent." });
        tx.update(cmpRef, { "stats.failed": FieldValue.increment(1) });
      }
    }
    tx.update(jobRef, { state: "ready", nextRunAt: now, leaseOwner: null, leaseUntil: 0, activeRecipientId: null });
    tx.update(cmpRef, { status: "queued", completedAt: null, errorMessage: null, updatedAt: timestamp });
  });
}

export async function cancelCampaign(userId: string, campaignId: string): Promise<void> {
  if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
    const db = await getMongoDb();
    const [camp, job] = await Promise.all([
      db.collection("campaigns").findOne(buildSafeOwnershipFilter(campaignId, userId)),
      db.collection("campaignJobs").findOne({ _id: campaignId as any }),
    ]);
    if (!camp || (camp as any).userId !== userId) throw new ApiError(404, "Campaign not found.", "NOT_FOUND");
    if (!["scheduled", "queued", "draft"].includes((camp as any).status) || (job as any)?.state === "running") {
      throw new ApiError(409, "Only a draft or a campaign waiting to send can be cancelled.", "CAMPAIGN_ACTIVE");
    }
    await Promise.all([
      db.collection("campaigns").updateOne({ _id: campaignId as any }, { $set: { status: "cancelled", updatedAt: new Date().toISOString() } }),
      db.collection("campaignJobs").updateOne({ _id: campaignId as any }, { $set: { state: "cancelled", leaseOwner: null, leaseUntil: 0 } }),
    ]);
    return;
  }

  const db = getAdminDb();
  const ref = db.collection("campaigns").doc(campaignId);
  const jobRef = db.collection("campaignJobs").doc(campaignId);
  await db.runTransaction(async (tx) => {
    const [campaign, job] = await Promise.all([tx.get(ref), tx.get(jobRef)]);
    if (!campaign.exists || campaign.data()?.userId !== userId) throw new ApiError(404, "Campaign not found.", "NOT_FOUND");
    if (!["scheduled", "queued", "draft"].includes(campaign.data()!.status) || job.data()?.state === "running") throw new ApiError(409, "Only a draft or a campaign waiting to send can be cancelled.", "CAMPAIGN_ACTIVE");
    if (job.exists) tx.update(jobRef, { state: "cancelled", leaseOwner: null, leaseUntil: 0 });
    tx.update(ref, { status: "cancelled", updatedAt: new Date().toISOString() });
  });
}
