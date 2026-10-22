import { z } from "zod";
import { getAdminDb, isFirebaseAdminConfigured } from "@/lib/firebase/admin";
import { getMongoDb, isMongoConfigured } from "@/lib/mongodb";
import type { AuthenticatedUser } from "@/lib/firebase/auth-middleware";
import type { SmtpConfig, UserProfile, UserSettings } from "@/types";
import { DEFAULT_SETTINGS } from "@/lib/store/defaults";
import { configured } from "./config";
import { ApiError } from "./errors";
import { decryptSecret, encryptSecret } from "./secrets";
import { settingsSchema, smtpSchema } from "./validation";

function cleanSettings(settings: Partial<UserSettings> = {}): UserSettings {
  const result = { ...DEFAULT_SETTINGS, ...settings, autoAppendUnsubscribe: true };
  if (result.gmail) result.gmail = { email: result.gmail.email, isConnected: result.gmail.isConnected, hasAppPassword: result.gmail.hasAppPassword };
  if (result.smtp) result.smtp = { ...result.smtp, pass: "" };
  return result;
}

export const stripUndefined = <T>(value: T): T => JSON.parse(JSON.stringify(value));

export async function getUserProfile(user: AuthenticatedUser): Promise<UserProfile> {
  const now = new Date().toISOString();

  if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
    const db = await getMongoDb();
    const old = (await db.collection("users").findOne({ _id: user.uid as any })) as any;
    if (old?.settings?.gmail?.appPassword || old?.settings?.smtp?.pass) {
      await saveUserSettings(user, settingsSchema.parse(old.settings));
      return getUserProfile(user);
    }
    const profile: UserProfile = stripUndefined({
      uid: user.uid,
      email: user.email,
      displayName: user.name || user.email.split("@")[0],
      photoURL: user.picture,
      settings: cleanSettings(old?.settings),
      createdAt: old?.createdAt || now,
      updatedAt: now,
    });
    if (!old) {
      await db.collection("users").updateOne(
        { _id: user.uid as any },
        { $setOnInsert: profile },
        { upsert: true }
      );
    }
    return profile;
  }

  const db = getAdminDb();
  const ref = db.collection("users").doc(user.uid);
  const snap = await ref.get();
  const old = snap.data();
  // Move legacy browser-readable passwords into the encrypted server-only collection.
  if (old?.settings?.gmail?.appPassword || old?.settings?.smtp?.pass) {
    await saveUserSettings(user, settingsSchema.parse(old.settings));
    return getUserProfile(user);
  }
  const profile: UserProfile = stripUndefined({
    uid: user.uid, email: user.email, displayName: user.name || user.email.split("@")[0],
    photoURL: user.picture, settings: cleanSettings(old?.settings),
    createdAt: old?.createdAt || now, updatedAt: now,
  });
  // Do not write settings from a stale read over a concurrent settings update.
  if (!snap.exists) {
    await db.runTransaction(async (tx) => {
      const latest = await tx.get(ref);
      if (!latest.exists) tx.create(ref, profile);
    });
  }
  return profile;
}

export function sameSmtpAccount(a: SmtpConfig, b: SmtpConfig): boolean {
  return a.host.toLowerCase() === b.host.toLowerCase() && a.port === b.port && a.secure === b.secure && a.user === b.user;
}

export async function saveUserSettings(user: AuthenticatedUser, input: z.infer<typeof settingsSchema>): Promise<UserSettings> {
  const now = new Date().toISOString();

  if (!isFirebaseAdminConfigured() && isMongoConfigured()) {
    const db = await getMongoDb();
    const [profileDoc, credentialsDoc] = await Promise.all([
      db.collection("users").findOne({ _id: user.uid as any }),
      db.collection("userCredentials").findOne({ _id: user.uid as any }),
    ]);

    const old = (profileDoc as any);
    const current = cleanSettings(old?.settings);
    const settings = cleanSettings({ ...current, ...input });
    const encrypted = (credentialsDoc as any)?.smtp as string | undefined;
    let saved = encrypted ? smtpSchema.parse(JSON.parse(decryptSecret(encrypted, user.uid))) : undefined;

    const changesConnection = input.gmail !== undefined || input.smtp !== undefined || input.deliveryMethod !== undefined;
    if (changesConnection) {
      const gmail = settings.deliveryMethod !== "custom_smtp";
      const candidate = gmail ? {
        host: "smtp.gmail.com", port: 465, secure: true,
        user: input.gmail?.email || settings.gmail?.email || input.smtp?.user || "",
        pass: input.gmail?.appPassword || input.smtp?.pass || "",
      } : input.smtp || settings.smtp;

      if (candidate?.user) {
        const smtp = smtpSchema.parse(candidate);
        if (!smtp.pass && saved && sameSmtpAccount(smtp, saved)) smtp.pass = saved.pass;
        if (!smtp.pass) throw new ApiError(400, "Enter a password for the selected sending account.", "SMTP_PASSWORD_REQUIRED");
        if (smtp.host.toLowerCase() === "smtp.gmail.com") smtp.pass = smtp.pass.replace(/\s/g, "");

        await db.collection("userCredentials").updateOne(
          { _id: user.uid as any },
          { $set: { uid: user.uid, smtp: encryptSecret(JSON.stringify(smtp), user.uid), updatedAt: now } },
          { upsert: true }
        );
        saved = smtp;
      }
    }

    if (saved) {
      settings.smtp = { ...saved, pass: "", hasPassword: true };
      settings.gmail = { email: settings.gmail?.email || "", isConnected: saved.host === "smtp.gmail.com", hasAppPassword: saved.host === "smtp.gmail.com" };
      if (saved.host === "smtp.gmail.com") settings.gmail.email = saved.user;
    }

    await db.collection("users").updateOne(
      { _id: user.uid as any },
      {
        $set: {
          uid: user.uid,
          email: user.email,
          displayName: user.name || user.email,
          settings: stripUndefined(settings),
          updatedAt: now,
        },
        $setOnInsert: { createdAt: now },
      },
      { upsert: true }
    );
    return settings;
  }

  const db = getAdminDb();
  const profileRef = db.collection("users").doc(user.uid);
  const secretRef = db.collection("userCredentials").doc(user.uid);
  return db.runTransaction(async (tx) => {
    const [profileDoc, credentialsDoc] = await Promise.all([tx.get(profileRef), tx.get(secretRef)]);
    const old = profileDoc.data();
    const current = cleanSettings(old?.settings);
    const settings = cleanSettings({ ...current, ...input });
    const encrypted = credentialsDoc.data()?.smtp as string | undefined;
    let saved = encrypted ? smtpSchema.parse(JSON.parse(decryptSecret(encrypted, user.uid))) : undefined;
    const changesConnection = input.gmail !== undefined || input.smtp !== undefined || input.deliveryMethod !== undefined;
    if (changesConnection) {
      const gmail = settings.deliveryMethod !== "custom_smtp";
      const candidate = gmail ? {
        host: "smtp.gmail.com", port: 465, secure: true,
        user: input.gmail?.email || settings.gmail?.email || input.smtp?.user || "",
        pass: input.gmail?.appPassword || input.smtp?.pass || "",
      } : input.smtp || settings.smtp;
      if (candidate?.user) {
        const smtp = smtpSchema.parse(candidate);
        if (!smtp.pass && saved && sameSmtpAccount(smtp, saved)) smtp.pass = saved.pass;
        if (!smtp.pass) throw new ApiError(400, "Enter a password for the selected sending account.", "SMTP_PASSWORD_REQUIRED");
        if (smtp.host.toLowerCase() === "smtp.gmail.com") smtp.pass = smtp.pass.replace(/\s/g, "");
        tx.set(secretRef, { smtp: encryptSecret(JSON.stringify(smtp), user.uid), updatedAt: new Date().toISOString() });
        saved = smtp;
      }
    }
    if (saved) {
      settings.smtp = { ...saved, pass: "", hasPassword: true };
      settings.gmail = { email: settings.gmail?.email || "", isConnected: saved.host === "smtp.gmail.com", hasAppPassword: saved.host === "smtp.gmail.com" };
      if (saved.host === "smtp.gmail.com") settings.gmail.email = saved.user;
    }
    // Replace the settings map so legacy plaintext nested fields are actually removed.
    const now = new Date().toISOString();
    if (profileDoc.exists) tx.update(profileRef, { settings: stripUndefined(settings), updatedAt: now });
    else tx.create(profileRef, stripUndefined({ uid: user.uid, email: user.email, displayName: user.name || user.email, settings, createdAt: now, updatedAt: now }));
    return settings;
  });
}

export function environmentSmtp(): SmtpConfig | null {
  if (configured(process.env.GMAIL_USER) && configured(process.env.GMAIL_APP_PASSWORD)) {
    return { host: "smtp.gmail.com", port: 465, secure: true, user: process.env.GMAIL_USER!.trim(), pass: process.env.GMAIL_APP_PASSWORD!.replace(/\s/g, "") };
  }
  if (configured(process.env.SMTP_HOST) && configured(process.env.SMTP_USER) && configured(process.env.SMTP_PASS)) {
    return smtpSchema.parse({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: process.env.SMTP_SECURE === "true" || process.env.SMTP_PORT === "465", user: process.env.SMTP_USER, pass: process.env.SMTP_PASS });
  }
  return null;
}

export async function resolveSmtp(user: AuthenticatedUser, override?: SmtpConfig): Promise<SmtpConfig> {
  if (override?.pass) return smtpSchema.parse(override);

  let encrypted: string | undefined;
  if (isFirebaseAdminConfigured()) {
    const snap = await getAdminDb().collection("userCredentials").doc(user.uid).get();
    encrypted = snap.data()?.smtp as string | undefined;
  } else if (isMongoConfigured()) {
    const db = await getMongoDb();
    const doc = await db.collection("userCredentials").findOne({ _id: user.uid as any });
    encrypted = (doc as any)?.smtp as string | undefined;
  }

  if (encrypted) {
    const saved = smtpSchema.parse(JSON.parse(decryptSecret(encrypted, user.uid)));
    if (override && !sameSmtpAccount(override, saved)) throw new ApiError(400, "Enter the password for this sending account.", "SMTP_PASSWORD_REQUIRED");
    return saved;
  }
  const smtp = environmentSmtp();
  if (smtp) {
    // A public Google signup must not grant use of the deployment owner's mail account.
    const allowed = [smtp.user, process.env.FROM_EMAIL, ...(process.env.SMTP_ALLOWED_USERS || "").split(",")].filter(Boolean).map((email) => email!.trim().toLowerCase());
    if (allowed.includes(user.email.toLowerCase())) {
      if (override && !sameSmtpAccount(override, smtp)) throw new ApiError(400, "Enter the password for this sending account.", "SMTP_PASSWORD_REQUIRED");
      return smtp;
    }
  }
  throw new ApiError(400, "Connect a Gmail or SMTP account in Settings before sending.", "SMTP_NOT_CONFIGURED");
}
