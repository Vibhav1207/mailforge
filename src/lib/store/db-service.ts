import {
  collection,
  doc,
  getDoc,
  getDocs,
  setDoc,
  updateDoc,
  deleteDoc,
  query,
  where,
  orderBy,
  limit,
  serverTimestamp,
} from "firebase/firestore";
import { db, isFirebaseConfigured } from "@/lib/firebase/client";
import {
  Contact,
  ContactList,
  Campaign,
  CampaignRecipient,
  EmailTemplate,
  UserProfile,
  UserSettings,
} from "@/types";
import { PREBUILT_TEMPLATES } from "@/lib/email/templates";

// In-memory / LocalStorage cache fallback for smooth development before Firebase keys are added
const LOCAL_STORAGE_KEY_PREFIX = "mailforge_v3_";

function getLocalStore<T>(key: string, defaultValue: T): T {
  if (typeof window === "undefined") return defaultValue;
  try {
    const raw = localStorage.getItem(LOCAL_STORAGE_KEY_PREFIX + key);
    return raw ? JSON.parse(raw) : defaultValue;
  } catch {
    return defaultValue;
  }
}

function setLocalStore<T>(key: string, value: T): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(LOCAL_STORAGE_KEY_PREFIX + key, JSON.stringify(value));
  } catch (e) {
    console.error("Local store error:", e);
  }
}

// Default initial user settings
export const DEFAULT_SETTINGS: UserSettings = {
  defaultFromName: "",
  defaultFromEmail: "",
  defaultReplyTo: "",
  timezone: "UTC",
  trackOpens: true,
  trackClicks: true,
  autoAppendUnsubscribe: true,
  deliveryMethod: "gmail_app_password",
};

// Helper to prevent hanging Firestore queries if offline or uninitialized
async function withTimeout<T>(promise: Promise<T>, ms = 1200, fallback: T): Promise<T> {
  let timer: any;
  const timeoutPromise = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(fallback), ms);
  });
  try {
    const res = await Promise.race([promise, timeoutPromise]);
    clearTimeout(timer);
    return res;
  } catch {
    clearTimeout(timer);
    return fallback;
  }
}

// ----------------------------------------------------------------------------
// USER PROFILE & SETTINGS
// ----------------------------------------------------------------------------
export async function syncUserProfile(
  user: { uid: string; email: string; displayName?: string | null; photoURL?: string | null }
): Promise<UserProfile> {
  const defaultProfile: UserProfile = {
    uid: user.uid,
    email: user.email,
    displayName: user.displayName || user.email.split("@")[0],
    photoURL: user.photoURL || undefined,
    settings: DEFAULT_SETTINGS,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  if (db && isFirebaseConfigured) {
    try {
      const userRef = doc(db, "users", user.uid);
      const snap = await withTimeout(getDoc(userRef), 1200, null);
      if (snap && snap.exists()) {
        const data = snap.data();
        const profileData: UserProfile = {
          uid: user.uid,
          email: user.email,
          displayName: data.displayName || defaultProfile.displayName,
          photoURL: data.photoURL || defaultProfile.photoURL,
          settings: { ...DEFAULT_SETTINGS, ...(data.settings || {}) },
          createdAt: data.createdAt || defaultProfile.createdAt,
          updatedAt: data.updatedAt || defaultProfile.updatedAt,
        };
        setLocalStore(`user_${user.uid}`, profileData);
        return profileData;
      } else {
        // Asynchronously save without blocking UI
        withTimeout(setDoc(userRef, defaultProfile), 1200, null).catch(() => {});
        setLocalStore(`user_${user.uid}`, defaultProfile);
        return defaultProfile;
      }
    } catch (e) {
      console.warn("Firestore syncUserProfile error:", e);
    }
  }

  // Fallback to local store
  const stored = getLocalStore<UserProfile | null>(`user_${user.uid}`, null);
  if (stored) return stored;
  setLocalStore(`user_${user.uid}`, defaultProfile);
  return defaultProfile;
}

export async function updateUserSettings(userId: string, settings: Partial<UserSettings>): Promise<UserSettings> {
  if (db && isFirebaseConfigured) {
    try {
      const userRef = doc(db, "users", userId);
      await updateDoc(userRef, {
        settings,
        updatedAt: new Date().toISOString(),
      });
    } catch (e) {
      console.warn("Firestore updateUserSettings error:", e);
    }
  }

  const profile = getLocalStore<UserProfile | null>(`user_${userId}`, null);
  const updatedSettings = { ...(profile?.settings || DEFAULT_SETTINGS), ...settings };
  if (profile) {
    profile.settings = updatedSettings;
    profile.updatedAt = new Date().toISOString();
    setLocalStore(`user_${userId}`, profile);
  }
  return updatedSettings;
}

// ----------------------------------------------------------------------------
// CONTACTS MANAGEMENT
// ----------------------------------------------------------------------------
export async function getContacts(userId: string): Promise<Contact[]> {
  if (db && isFirebaseConfigured) {
    try {
      const q = query(collection(db, "contacts"), where("userId", "==", userId));
      const snap = await withTimeout(getDocs(q), 1500, null);
      if (snap) {
        const list: Contact[] = [];
        snap.forEach((d) => list.push({ ...(d.data() as Contact), id: d.id }));
        if (list.length > 0) {
          return list.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
        }
      }
    } catch (e) {
      console.warn("Firestore getContacts fallback:", e);
    }
  }

  return getLocalStore<Contact[]>(`contacts_${userId}`, []);
}

export async function saveContact(contact: Contact): Promise<Contact> {
  const timestamp = new Date().toISOString();
  const contactData: Contact = {
    ...contact,
    updatedAt: timestamp,
    createdAt: contact.createdAt || timestamp,
  };

  if (db && isFirebaseConfigured) {
    try {
      withTimeout(setDoc(doc(db, "contacts", contact.id), contactData), 1500, null).catch(() => {});
    } catch (e) {
      console.warn("Firestore saveContact fallback:", e);
    }
  }

  const list = getLocalStore<Contact[]>(`contacts_${contact.userId}`, []);
  const idx = list.findIndex((c) => c.id === contact.id);
  if (idx >= 0) {
    list[idx] = contactData;
  } else {
    list.unshift(contactData);
  }
  setLocalStore(`contacts_${contact.userId}`, list);
  return contactData;
}

export async function deleteContact(userId: string, contactId: string): Promise<void> {
  if (db && isFirebaseConfigured) {
    try {
      withTimeout(deleteDoc(doc(db, "contacts", contactId)), 1500, null).catch(() => {});
    } catch (e) {
      console.warn("Firestore deleteContact fallback:", e);
    }
  }

  const list = getLocalStore<Contact[]>(`contacts_${userId}`, []);
  setLocalStore(`contacts_${userId}`, list.filter((c) => c.id !== contactId));
}

// ----------------------------------------------------------------------------
// CAMPAIGNS MANAGEMENT
// ----------------------------------------------------------------------------
export async function getCampaigns(userId: string): Promise<Campaign[]> {
  if (db && isFirebaseConfigured) {
    try {
      const q = query(collection(db, "campaigns"), where("userId", "==", userId));
      const snap = await withTimeout(getDocs(q), 1500, null);
      if (snap) {
        const list: Campaign[] = [];
        snap.forEach((d) => list.push({ ...(d.data() as Campaign), id: d.id }));
        if (list.length > 0) {
          return list.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
        }
      }
    } catch (e) {
      console.warn("Firestore getCampaigns fallback:", e);
    }
  }

  return getLocalStore<Campaign[]>(`campaigns_${userId}`, []);
}

export async function getCampaignById(userId: string, campaignId: string): Promise<Campaign | null> {
  if (db && isFirebaseConfigured) {
    try {
      const snap = await getDoc(doc(db, "campaigns", campaignId));
      if (snap.exists() && snap.data().userId === userId) {
        return { ...(snap.data() as Campaign), id: snap.id };
      }
    } catch (e) {
      console.warn("Firestore getCampaignById fallback:", e);
    }
  }

  const list = getLocalStore<Campaign[]>(`campaigns_${userId}`, []);
  return list.find((c) => c.id === campaignId) || null;
}

export async function saveCampaign(campaign: Campaign): Promise<Campaign> {
  const timestamp = new Date().toISOString();
  const campaignData: Campaign = {
    ...campaign,
    updatedAt: timestamp,
    createdAt: campaign.createdAt || timestamp,
  };

  if (db && isFirebaseConfigured) {
    try {
      await setDoc(doc(db, "campaigns", campaign.id), campaignData);
      return campaignData;
    } catch (e) {
      console.warn("Firestore saveCampaign fallback:", e);
    }
  }

  const list = getLocalStore<Campaign[]>(`campaigns_${campaign.userId}`, []);
  const idx = list.findIndex((c) => c.id === campaign.id);
  if (idx >= 0) {
    list[idx] = campaignData;
  } else {
    list.unshift(campaignData);
  }
  setLocalStore(`campaigns_${campaign.userId}`, list);
  return campaignData;
}

export async function deleteCampaign(userId: string, campaignId: string): Promise<void> {
  if (db && isFirebaseConfigured) {
    try {
      await deleteDoc(doc(db, "campaigns", campaignId));
      return;
    } catch (e) {
      console.warn("Firestore deleteCampaign fallback:", e);
    }
  }

  const list = getLocalStore<Campaign[]>(`campaigns_${userId}`, []);
  setLocalStore(`campaigns_${userId}`, list.filter((c) => c.id !== campaignId));
}

export async function getCampaignRecipients(userId: string, campaignId: string): Promise<CampaignRecipient[]> {
  if (db && isFirebaseConfigured) {
    try {
      const q = query(
        collection(db, "campaignRecipients"),
        where("campaignId", "==", campaignId),
        where("userId", "==", userId)
      );
      const snap = await withTimeout(getDocs(q), 1500, null);
      if (snap) {
        const list: CampaignRecipient[] = [];
        snap.forEach((d) => list.push({ ...(d.data() as CampaignRecipient), id: d.id }));
        if (list.length > 0) return list;
      }
    } catch (e) {
      console.warn("Firestore getCampaignRecipients fallback:", e);
    }
  }

  return getLocalStore<CampaignRecipient[]>(`recipients_${campaignId}`, []);
}

export async function saveCampaignRecipients(campaignId: string, recipients: CampaignRecipient[]): Promise<void> {
  if (db && isFirebaseConfigured) {
    try {
      for (const r of recipients) {
        withTimeout(setDoc(doc(db, "campaignRecipients", r.id), r), 1500, null).catch(() => {});
      }
    } catch (e) {
      console.warn("Firestore saveCampaignRecipients fallback:", e);
    }
  }

  setLocalStore(`recipients_${campaignId}`, recipients);
}

// ----------------------------------------------------------------------------
// EMAIL TEMPLATES
// ----------------------------------------------------------------------------
export async function getTemplates(userId: string): Promise<EmailTemplate[]> {
  let userTemplates: EmailTemplate[] = [];

  if (db && isFirebaseConfigured) {
    try {
      const q = query(collection(db, "emailTemplates"), where("userId", "==", userId));
      const snap = await getDocs(q);
      snap.forEach((d) => userTemplates.push({ ...(d.data() as EmailTemplate), id: d.id }));
    } catch (e) {
      console.warn("Firestore getTemplates fallback:", e);
    }
  } else {
    userTemplates = getLocalStore<EmailTemplate[]>(`templates_${userId}`, []);
  }

  return [...PREBUILT_TEMPLATES, ...userTemplates];
}

export async function saveTemplate(template: EmailTemplate): Promise<EmailTemplate> {
  if (db && isFirebaseConfigured) {
    try {
      await setDoc(doc(db, "emailTemplates", template.id), template);
      return template;
    } catch (e) {
      console.warn("Firestore saveTemplate fallback:", e);
    }
  }

  if (template.userId) {
    const list = getLocalStore<EmailTemplate[]>(`templates_${template.userId}`, []);
    const idx = list.findIndex((t) => t.id === template.id);
    if (idx >= 0) {
      list[idx] = template;
    } else {
      list.unshift(template);
    }
    setLocalStore(`templates_${template.userId}`, list);
  }
  return template;
}

export async function deleteTemplate(userId: string, templateId: string): Promise<void> {
  if (db && isFirebaseConfigured) {
    try {
      await deleteDoc(doc(db, "emailTemplates", templateId));
      return;
    } catch (e) {
      console.warn("Firestore deleteTemplate fallback:", e);
    }
  }

  const list = getLocalStore<EmailTemplate[]>(`templates_${userId}`, []);
  setLocalStore(`templates_${userId}`, list.filter((t) => t.id !== templateId));
}
