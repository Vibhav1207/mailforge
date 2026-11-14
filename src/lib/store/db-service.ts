"use client";

import type { Contact, Campaign, CampaignRecipient, EmailTemplate, UserProfile, UserSettings } from "@/types";
import { PREBUILT_TEMPLATES } from "@/lib/email/templates";
import { apiRequest } from "@/lib/api-client";
export { DEFAULT_SETTINGS } from "./defaults";

const jsonBody = (value: unknown, method = "POST"): RequestInit => ({ method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(value) });

// Client-side cache to enable instant tab switching and eliminate redundant network roundtrips
interface CacheEntry<T> {
  data: T;
  timestamp: number;
}
const clientCache = new Map<string, CacheEntry<any>>();
const CACHE_TTL_MS = 30_000; // 30s cache TTL

function getFromCache<T>(key: string): T | null {
  const entry = clientCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
    clientCache.delete(key);
    return null;
  }
  return entry.data as T;
}

function setToCache<T>(key: string, data: T): void {
  clientCache.set(key, { data, timestamp: Date.now() });
}

export function invalidateCache(prefix?: string): void {
  if (!prefix) {
    clientCache.clear();
    return;
  }
  for (const key of clientCache.keys()) {
    if (key.startsWith(prefix)) clientCache.delete(key);
  }
}

async function allPages<T>(path: string, key: string): Promise<T[]> {
  const result: T[] = [];
  let cursor: string | null = null;
  const sep = path.includes("?") ? "&" : "?";
  do {
    const query = cursor ? `${sep}cursor=${encodeURIComponent(cursor)}&limit=100` : `${sep}limit=100`;
    const data: Record<string, unknown> = await apiRequest(`${path}${query}`);
    result.push(...((data[key] as T[]) || []));
    cursor = (data.nextCursor as string | null) || null;
  } while (cursor);
  return result;
}

export async function syncUserProfile(_user: { uid: string; email: string; displayName?: string | null; photoURL?: string | null }): Promise<UserProfile> {
  return (await apiRequest<{ profile: UserProfile }>("/api/profile")).profile;
}

export async function updateUserSettings(_userId: string, settings: Partial<UserSettings>): Promise<UserSettings> {
  invalidateCache("profile");
  return (await apiRequest<{ settings: UserSettings }>("/api/settings", jsonBody(settings, "PATCH"))).settings;
}

export async function getContacts(userId: string, forceRefresh = false): Promise<Contact[]> {
  if (!userId) return [];
  const cacheKey = `contacts_${userId}`;
  if (!forceRefresh) {
    const cached = getFromCache<Contact[]>(cacheKey);
    if (cached) return cached;
  }
  const contacts = (await allPages<Contact>("/api/contacts", "contacts")).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  setToCache(cacheKey, contacts);
  return contacts;
}

export async function saveContact(contact: Contact): Promise<Contact> {
  invalidateCache("contacts");
  return (await apiRequest<{ contact: Contact }>("/api/contacts", jsonBody(contact))).contact;
}

export async function deleteContact(_userId: string, contactId: string): Promise<void> {
  invalidateCache("contacts");
  await apiRequest(`/api/contacts/${encodeURIComponent(contactId)}`, { method: "DELETE" });
}

export async function getCampaigns(userId: string, forceRefresh = false): Promise<Campaign[]> {
  if (!userId) return [];
  const cacheKey = `campaigns_${userId}`;
  if (!forceRefresh) {
    const cached = getFromCache<Campaign[]>(cacheKey);
    if (cached) return cached;
  }
  const campaigns = (await allPages<Campaign>("/api/campaigns", "campaigns")).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  setToCache(cacheKey, campaigns);
  return campaigns;
}

export async function getCampaignById(_userId: string, campaignId: string): Promise<Campaign | null> {
  return (await apiRequest<{ campaign: Campaign }>(`/api/campaigns/${encodeURIComponent(campaignId)}`)).campaign;
}

export async function saveCampaign(campaign: Campaign): Promise<Campaign> {
  invalidateCache("campaigns");
  if (campaign.status === "cancelled") {
    return (await apiRequest<{ campaign: Campaign }>(`/api/campaigns/${encodeURIComponent(campaign.id)}`, jsonBody({ status: "cancelled" }, "PATCH"))).campaign;
  }
  return (await apiRequest<{ campaign: Campaign }>("/api/campaigns", jsonBody(campaign))).campaign;
}

export async function deleteCampaign(_userId: string, campaignId: string): Promise<void> {
  invalidateCache("campaigns");
  await apiRequest(`/api/campaigns/${encodeURIComponent(campaignId)}`, { method: "DELETE" });
}

export async function getCampaignRecipients(_userId: string, campaignId: string): Promise<CampaignRecipient[]> {
  return (await apiRequest<{ recipients: CampaignRecipient[] }>(`/api/campaigns/${encodeURIComponent(campaignId)}/recipients`)).recipients;
}

export async function saveCampaignRecipients(_campaignId: string, _recipients: CampaignRecipient[]): Promise<void> {
  // Campaign recipients are saved on the server-side during /api/campaigns/send
}

export async function getTemplates(userId: string, forceRefresh = false): Promise<EmailTemplate[]> {
  const cacheKey = `templates_${userId || "all"}`;
  if (!forceRefresh) {
    const cached = getFromCache<EmailTemplate[]>(cacheKey);
    if (cached) return cached;
  }
  const { templates } = await apiRequest<{ templates: EmailTemplate[] }>("/api/templates");
  const combined = [...PREBUILT_TEMPLATES, ...(templates || [])];
  setToCache(cacheKey, combined);
  return combined;
}

export async function saveTemplate(template: EmailTemplate): Promise<EmailTemplate> {
  invalidateCache("templates");
  return (await apiRequest<{ template: EmailTemplate }>("/api/templates", jsonBody(template))).template;
}

export async function deleteTemplate(_userId: string, templateId: string): Promise<void> {
  invalidateCache("templates");
  await apiRequest(`/api/templates/${encodeURIComponent(templateId)}`, { method: "DELETE" });
}
