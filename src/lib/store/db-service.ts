"use client";

import type { Contact, Campaign, CampaignRecipient, EmailTemplate, UserProfile, UserSettings } from "@/types";
import { PREBUILT_TEMPLATES } from "@/lib/email/templates";
import { apiRequest } from "@/lib/api-client";
export { DEFAULT_SETTINGS } from "./defaults";

const jsonBody = (value: unknown, method = "POST"): RequestInit => ({ method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(value) });

async function allPages<T>(path: string, key: string): Promise<T[]> {
  const result: T[] = [];
  let cursor: string | null = null;
  do {
    const data: Record<string, unknown> = await apiRequest(`${path}${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`);
    result.push(...data[key] as T[]);
    cursor = data.nextCursor as string | null;
  } while (cursor);
  return result;
}

export async function syncUserProfile(_user: { uid: string; email: string; displayName?: string | null; photoURL?: string | null }): Promise<UserProfile> {
  return (await apiRequest<{ profile: UserProfile }>("/api/profile")).profile;
}

export async function updateUserSettings(_userId: string, settings: Partial<UserSettings>): Promise<UserSettings> {
  return (await apiRequest<{ settings: UserSettings }>("/api/settings", jsonBody(settings, "PATCH"))).settings;
}

export async function getContacts(_userId: string): Promise<Contact[]> {
  return (await allPages<Contact>("/api/contacts", "contacts")).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export async function saveContact(contact: Contact): Promise<Contact> {
  return (await apiRequest<{ contact: Contact }>("/api/contacts", jsonBody(contact))).contact;
}

export async function deleteContact(_userId: string, contactId: string): Promise<void> {
  await apiRequest(`/api/contacts/${encodeURIComponent(contactId)}`, { method: "DELETE" });
}

export async function getCampaigns(_userId: string): Promise<Campaign[]> {
  return (await allPages<Campaign>("/api/campaigns", "campaigns")).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export async function getCampaignById(_userId: string, campaignId: string): Promise<Campaign | null> {
  return (await apiRequest<{ campaign: Campaign }>(`/api/campaigns/${encodeURIComponent(campaignId)}`)).campaign;
}

export async function saveCampaign(campaign: Campaign): Promise<Campaign> {
  if (campaign.status === "cancelled") {
    return (await apiRequest<{ campaign: Campaign }>(`/api/campaigns/${encodeURIComponent(campaign.id)}`, jsonBody({ status: "cancelled" }, "PATCH"))).campaign;
  }
  return (await apiRequest<{ campaign: Campaign }>("/api/campaigns", jsonBody(campaign))).campaign;
}

export async function deleteCampaign(_userId: string, campaignId: string): Promise<void> {
  await apiRequest(`/api/campaigns/${encodeURIComponent(campaignId)}`, { method: "DELETE" });
}

export async function getCampaignRecipients(_userId: string, campaignId: string): Promise<CampaignRecipient[]> {
  return (await apiRequest<{ recipients: CampaignRecipient[] }>(`/api/campaigns/${encodeURIComponent(campaignId)}/recipients`)).recipients;
}

export async function saveCampaignRecipients(_campaignId: string, _recipients: CampaignRecipient[]): Promise<void> {
  // Campaign recipients are saved on the server-side during /api/campaigns/send
}

export async function getTemplates(_userId: string): Promise<EmailTemplate[]> {
  const { templates } = await apiRequest<{ templates: EmailTemplate[] }>("/api/templates");
  return [...PREBUILT_TEMPLATES, ...templates];
}

export async function saveTemplate(template: EmailTemplate): Promise<EmailTemplate> {
  return (await apiRequest<{ template: EmailTemplate }>("/api/templates", jsonBody(template))).template;
}

export async function deleteTemplate(_userId: string, templateId: string): Promise<void> {
  await apiRequest(`/api/templates/${encodeURIComponent(templateId)}`, { method: "DELETE" });
}
