"use client";

import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import Papa from "papaparse";
import { useAuth } from "@/context/auth-context";
import {
  getContacts,
  getTemplates,
  saveCampaign,
  saveCampaignRecipients,
} from "@/lib/store/db-service";
import { apiFetch } from "@/lib/api-client";
import { Contact, EmailTemplate, Campaign, CampaignRecipient } from "@/types";
import {
  parseEmailList,
  interpolateVariables,
  htmlToPlainText,
  isValidEmail,
  formatDate,
} from "@/lib/utils";
import {
  Send,
  Upload,
  Users,
  Eye,
  FileCode,
  Sparkles,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  Clock,
  Trash2,
  X,
  FileText,
  Save,
  Check,
  ChevronDown,
  Mail,
  RefreshCw,
  Bold,
  Italic,
  List,
  Heading,
  Link as LinkIcon,
  Code,
  MousePointerClick,
  Zap,
  Server,
} from "lucide-react";

interface RecipientItem {
  id: string;
  email: string;
  firstName?: string;
  lastName?: string;
  company?: string;
  customFields?: Record<string, string>;
  selected?: boolean;
}

export default function ComposeEmailPage() {
  const router = useRouter();
  const { user, profile } = useAuth();
  const userId = user?.uid || profile?.uid || "";

  // Composer Form State
  const [campaignName, setCampaignName] = useState("Product Announcement " + new Date().toLocaleDateString());
  const [subject, setSubject] = useState("");
  const [fromName, setFromName] = useState(profile?.settings?.defaultFromName || "MailForge Team");
  const [fromEmail, setFromEmail] = useState(
    profile?.settings?.defaultFromEmail ||
    profile?.settings?.gmail?.email ||
    profile?.settings?.smtp?.user ||
    user?.email ||
    ""
  );
  const [replyTo, setReplyTo] = useState(profile?.settings?.defaultReplyTo || "");
  const [htmlContent, setHtmlContent] = useState("");
  const [textContent, setTextContent] = useState("");
  const [editorMode, setEditorMode] = useState<"visual" | "html">("visual");

  // Telemetry & Tracking
  const [trackOpens, setTrackOpens] = useState(profile?.settings?.trackOpens !== false);
  const [trackClicks, setTrackClicks] = useState(profile?.settings?.trackClicks !== false);

  // Recipient Management State
  const [recipientTab, setRecipientTab] = useState<"paste" | "csv" | "contacts">("paste");
  const [rawPasteEmails, setRawPasteEmails] = useState("");
  const [recipients, setRecipients] = useState<RecipientItem[]>([]);
  const [invalidAddresses, setInvalidAddresses] = useState<string[]>([]);
  const [duplicateCount, setDuplicateCount] = useState(0);

  // Saved Contacts Picker
  const [savedContacts, setSavedContacts] = useState<Contact[]>([]);
  const [selectedContactIds, setSelectedContactIds] = useState<Set<string>>(new Set());

  // Templates
  const [availableTemplates, setAvailableTemplates] = useState<EmailTemplate[]>([]);
  const [templateModalOpen, setTemplateModalOpen] = useState(false);

  // Preview & Test State
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewRecipientIndex, setPreviewRecipientIndex] = useState(0);
  const [sendingTest, setSendingTest] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  // Auto-Save Draft State
  const [draftId, setDraftId] = useState<string>(`draft_${Date.now()}`);
  const [lastSaved, setLastSaved] = useState<string | null>(null);
  const [savingDraft, setSavingDraft] = useState(false);

  // Sending & Scheduling Controls
  const [scheduleMode, setScheduleMode] = useState(false);
  const [scheduleDateTime, setScheduleDateTime] = useState("");
  const [confirmSendOpen, setConfirmSendOpen] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [sendProgress, setSendProgress] = useState<{
    sent: number;
    failed: number;
    total: number;
    statusText: string;
  } | null>(null);

  const editorRef = useRef<HTMLDivElement>(null);

  // Load saved contacts and templates on mount
  useEffect(() => {
    async function loadData() {
      try {
        const [cnts, tmpls] = await Promise.all([
          getContacts(userId),
          getTemplates(userId),
        ]);
        setSavedContacts(cnts);
        setAvailableTemplates(tmpls);

        // Load default template if empty
        if (tmpls.length > 0 && !htmlContent) {
          setSubject(tmpls[0].subject);
          setHtmlContent(tmpls[0].htmlContent);
          setTextContent(tmpls[0].textContent || "");
        }
      } catch (err) {
        console.error("Failed to load initial composer data:", err);
      }
    }
    loadData();
  }, [userId]);

  // Update profile default sender values if changed
  useEffect(() => {
    if (profile?.settings) {
      if (profile.settings.defaultFromName && fromName === "MailForge Team") {
        setFromName(profile.settings.defaultFromName);
      }
      if (profile.settings.defaultFromEmail && (!fromEmail || fromEmail === "onboarding@resend.dev")) {
        setFromEmail(profile.settings.defaultFromEmail);
      } else if (!fromEmail && (profile.settings.gmail?.email || profile.settings.smtp?.user)) {
        setFromEmail(profile.settings.gmail?.email || profile.settings.smtp?.user || "");
      }
      if (profile.settings.trackOpens !== undefined) {
        setTrackOpens(profile.settings.trackOpens);
      }
      if (profile.settings.trackClicks !== undefined) {
        setTrackClicks(profile.settings.trackClicks);
      }
    }
  }, [profile]);

  // Sync editor innerHTML when in visual mode
  useEffect(() => {
    if (editorMode === "visual" && editorRef.current) {
      if (editorRef.current.innerHTML !== htmlContent) {
        editorRef.current.innerHTML = htmlContent;
      }
    }
  }, [editorMode]);

  // Auto-save draft debounce
  useEffect(() => {
    if (!subject && !htmlContent) return;
    const timer = setTimeout(async () => {
      await autoSaveDraft();
    }, 4000);
    return () => clearTimeout(timer);
  }, [subject, htmlContent, fromName, fromEmail, recipients, campaignName]);

  const autoSaveDraft = async () => {
    try {
      setSavingDraft(true);
      const draftCampaign: Campaign = {
        id: draftId,
        userId,
        name: campaignName,
        subject: subject || "Untitled Draft",
        fromName,
        fromEmail,
        replyTo,
        htmlContent,
        textContent: textContent || htmlToPlainText(htmlContent),
        recipientCount: recipients.length,
        status: "draft",
        stats: { total: recipients.length, sent: 0, delivered: 0, bounced: 0, failed: 0, unsubscribed: 0 },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      await saveCampaign(draftCampaign);
      setLastSaved(new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
    } catch (err) {
      console.warn("Draft auto-save warning:", err);
    } finally {
      setSavingDraft(false);
    }
  };

  // Process raw pasted emails
  const handleParsePastedEmails = () => {
    if (!rawPasteEmails.trim()) return;
    const parsed = parseEmailList(rawPasteEmails);
    const newItems: RecipientItem[] = parsed.valid.map((email) => ({
      id: `rcp_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      email,
      firstName: "",
      lastName: "",
      company: "",
      selected: true,
    }));

    // Deduplicate against existing list
    const existingEmails = new Set(recipients.map((r) => r.email));
    const merged = [...recipients];
    let addedDupes = 0;

    for (const item of newItems) {
      if (!existingEmails.has(item.email)) {
        existingEmails.add(item.email);
        merged.push(item);
      } else {
        addedDupes++;
      }
    }

    setRecipients(merged);
    setInvalidAddresses(parsed.invalid);
    setDuplicateCount(parsed.duplicates + addedDupes);
    setRawPasteEmails("");
  };

  // Handle CSV file upload
  const handleCsvUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    Papa.parse<any>(file, {
      header: true,
      skipEmptyLines: true,
      complete: (results) => {
        const rows = results.data;
        const validList: RecipientItem[] = [];
        const invalidList: string[] = [];
        let dupes = 0;
        const existingEmails = new Set(recipients.map((r) => r.email));

        for (const row of rows) {
          // Identify email column flexibly
          const emailKey = Object.keys(row).find((k) =>
            k.toLowerCase().includes("email") || k.toLowerCase() === "mail"
          );
          const rawEmail = emailKey ? String(row[emailKey] || "").trim().toLowerCase() : "";

          const firstNameKey = Object.keys(row).find((k) =>
            k.toLowerCase().includes("first") || k.toLowerCase() === "name"
          );
          const lastNameKey = Object.keys(row).find((k) => k.toLowerCase().includes("last"));
          const companyKey = Object.keys(row).find((k) =>
            k.toLowerCase().includes("company") || k.toLowerCase().includes("org")
          );

          if (isValidEmail(rawEmail)) {
            if (existingEmails.has(rawEmail)) {
              dupes++;
            } else {
              existingEmails.add(rawEmail);
              validList.push({
                id: `rcp_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
                email: rawEmail,
                firstName: firstNameKey ? row[firstNameKey] : "",
                lastName: lastNameKey ? row[lastNameKey] : "",
                company: companyKey ? row[companyKey] : "",
                customFields: row,
                selected: true,
              });
            }
          } else if (rawEmail) {
            invalidList.push(rawEmail);
          }
        }

        setRecipients([...recipients, ...validList]);
        setInvalidAddresses(invalidList);
        setDuplicateCount(dupes);
        e.target.value = "";
      },
      error: (err) => {
        console.error("CSV Parse error:", err);
      },
    });
  };

  // Add selected saved contacts
  const handleAddSelectedSavedContacts = () => {
    const selected = savedContacts.filter((c) => selectedContactIds.has(c.id) && c.status === "active");
    const existingEmails = new Set(recipients.map((r) => r.email));
    const merged = [...recipients];
    let dupes = 0;

    for (const c of selected) {
      if (!existingEmails.has(c.email)) {
        existingEmails.add(c.email);
        merged.push({
          id: c.id,
          email: c.email,
          firstName: c.firstName,
          lastName: c.lastName,
          company: c.company,
          customFields: c.customFields,
          selected: true,
        });
      } else {
        dupes++;
      }
    }

    setRecipients(merged);
    setDuplicateCount(dupes);
    setSelectedContactIds(new Set());
  };

  // Remove recipient
  const handleRemoveRecipient = (id: string) => {
    setRecipients(recipients.filter((r) => r.id !== id));
  };

  // Toggle recipient selection
  const handleToggleRecipient = (id: string) => {
    setRecipients(
      recipients.map((r) => (r.id === id ? { ...r, selected: !r.selected } : r))
    );
  };

  // Insert personalization variable
  const insertVariable = (variable: string) => {
    const token = `{{${variable}}}`;
    if (editorMode === "visual" && editorRef.current) {
      editorRef.current.focus();
      document.execCommand("insertText", false, token);
      setHtmlContent(editorRef.current.innerHTML);
    } else {
      setHtmlContent((prev) => prev + " " + token);
    }
  };

  // Format action in visual editor
  const formatDoc = (cmd: string, val: string | undefined = undefined) => {
    if (editorMode === "visual" && editorRef.current) {
      editorRef.current.focus();
      document.execCommand(cmd, false, val);
      setHtmlContent(editorRef.current.innerHTML);
    }
  };

  // Send preview test email to current user
  const handleSendTestEmail = async () => {
    setSendingTest(true);
    setTestResult(null);
    try {
      const res = await apiFetch("/api/send-test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          to: profile?.email || user?.email,
          subject,
          htmlContent,
          textContent,
          fromName,
          fromEmail,
          replyTo,
          smtpConfig: profile?.settings?.smtp?.pass
            ? profile.settings.smtp
            : profile?.settings?.gmail?.appPassword
            ? {
                host: "smtp.gmail.com",
                port: 465,
                secure: true,
                user: profile.settings.gmail.email,
                pass: profile.settings.gmail.appPassword,
              }
            : undefined,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to dispatch test email");
      }

      setTestResult({
        success: true,
        message: `Test email sent successfully to ${data.sentTo}`,
      });
    } catch (err: any) {
      setTestResult({
        success: false,
        message: err.message || "Failed to send test email",
      });
    } finally {
      setSendingTest(false);
    }
  };

  // Active chosen recipients (only those checked)
  const activeSelectedRecipients = recipients.filter((r) => r.selected !== false);

  // Dispatch campaign immediately or schedule
  const handleExecuteSend = async () => {
    if (activeSelectedRecipients.length === 0) return;
    setConfirmSendOpen(false);
    setIsProcessing(true);
    setSendProgress({
      sent: 0,
      failed: 0,
      total: activeSelectedRecipients.length,
      statusText: "Initializing campaign batches and verifying suppressions...",
    });

    const campaignId = `cmp_${Date.now()}`;

    // If scheduled for future
    if (scheduleMode && scheduleDateTime) {
      const scheduledCampaign: Campaign = {
        id: campaignId,
        userId,
        name: campaignName,
        subject,
        fromName,
        fromEmail,
        replyTo,
        htmlContent,
        textContent: textContent || htmlToPlainText(htmlContent),
        recipientCount: activeSelectedRecipients.length,
        status: "scheduled",
        scheduledFor: new Date(scheduleDateTime).toISOString(),
        stats: {
          total: activeSelectedRecipients.length,
          sent: 0,
          delivered: 0,
          bounced: 0,
          failed: 0,
          unsubscribed: 0,
          opened: 0,
          clicked: 0,
        },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      await saveCampaign(scheduledCampaign);
      setIsProcessing(false);
      router.push(`/dashboard/campaigns/${campaignId}`);
      return;
    }

    try {
      const res = await apiFetch("/api/campaigns/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          campaignId,
          name: campaignName,
          subject,
          htmlContent,
          textContent: textContent || htmlToPlainText(htmlContent),
          fromName,
          fromEmail,
          replyTo,
          recipients: activeSelectedRecipients,
          idempotencyKey: `idemp_${campaignId}`,
          trackOpens,
          trackClicks,
          smtpConfig: profile?.settings?.smtp?.pass
            ? profile.settings.smtp
            : profile?.settings?.gmail?.appPassword
            ? {
                host: "smtp.gmail.com",
                port: 465,
                secure: true,
                user: profile.settings.gmail.email,
                pass: profile.settings.gmail.appPassword,
              }
            : undefined,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to process campaign");
      }

      setSendProgress({
        sent: data.stats?.sent || activeSelectedRecipients.length,
        failed: data.stats?.failed || 0,
        total: activeSelectedRecipients.length,
        statusText: "Batch delivery complete!",
      });

      // Update local storage representation
      const campaignRecord: Campaign = {
        id: campaignId,
        userId,
        name: campaignName,
        subject,
        fromName,
        fromEmail,
        replyTo,
        htmlContent,
        textContent: textContent || htmlToPlainText(htmlContent),
        recipientCount: activeSelectedRecipients.length,
        status: data.status || "completed",
        stats: {
          total: activeSelectedRecipients.length,
          sent: data.stats?.sent || activeSelectedRecipients.length,
          delivered: 0,
          bounced: 0,
          failed: data.stats?.failed || 0,
          unsubscribed: data.stats?.suppressed || 0,
        },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
      };
      await saveCampaign(campaignRecord);

      // Persist individual recipient dispatch records for campaign report
      const campaignRecipientRecords: CampaignRecipient[] = activeSelectedRecipients.map((rcp, idx) => ({
        id: `rcp_${campaignId}_${idx}`,
        campaignId,
        userId,
        email: rcp.email,
        firstName: rcp.firstName,
        lastName: rcp.lastName,
        company: rcp.company,
        status: "sent",
        attempts: 1,
        sentAt: new Date().toISOString(),
      }));
      await saveCampaignRecipients(campaignId, campaignRecipientRecords);

      setTimeout(() => {
        setIsProcessing(false);
        router.push(`/dashboard/campaigns/${campaignId}`);
      }, 1200);
    } catch (err: any) {
      console.error("Execution send error:", err);
      alert(err.message || "Failed to deliver campaign");
      setIsProcessing(false);
    }
  };

  // Preview interpolation recipient
  const previewTarget = activeSelectedRecipients[previewRecipientIndex] || {
    email: user?.email || profile?.email || "recipient@example.com",
    firstName: user?.displayName?.split(" ")[0] || "Recipient",
    lastName: user?.displayName?.split(" ")[1] || "",
    company: "",
  };

  const previewSubject = interpolateVariables(subject, {
    ...previewTarget,
    fromName,
  });

  const previewHtml = interpolateVariables(htmlContent, {
    ...previewTarget,
    fromName,
    unsubscribeUrl: `${typeof window !== "undefined" ? window.location.origin : ""}/unsubscribe`,
  });

  return (
    <div className="space-y-6 pb-12">
      {/* Header & Campaign Name Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-200 pb-5">
        <div className="flex-1 max-w-xl">
          <input
            type="text"
            value={campaignName}
            onChange={(e) => setCampaignName(e.target.value)}
            className="text-2xl font-bold tracking-tight text-slate-900 bg-transparent border-0 border-b border-transparent hover:border-slate-300 focus:border-blue-500 focus:ring-0 px-0 py-1 w-full"
            placeholder="Campaign Name"
          />
          <div className="flex items-center gap-3 mt-1 text-xs text-slate-500">
            <span className="flex items-center gap-1">
              <Save className="w-3.5 h-3.5" />
              {savingDraft
                ? "Saving draft..."
                : lastSaved
                ? `Saved as draft at ${lastSaved}`
                : "Auto-save active"}
            </span>
            <span>•</span>
            <span>{activeSelectedRecipients.length} recipients selected</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setPreviewOpen(true)}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-slate-700 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 shadow-sm transition-all"
          >
            <Eye className="w-4 h-4 text-slate-500" />
            <span>Preview</span>
          </button>

          <button
            onClick={handleSendTestEmail}
            disabled={sendingTest || !subject || !htmlContent}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-slate-700 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 shadow-sm transition-all disabled:opacity-50"
          >
            <Mail className="w-4 h-4 text-slate-500" />
            <span>{sendingTest ? "Sending Test..." : "Send Test to Me"}</span>
          </button>

          <button
            onClick={() => setConfirmSendOpen(true)}
            disabled={activeSelectedRecipients.length === 0 || !subject.trim() || !htmlContent.trim()}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg shadow-sm transition-all disabled:opacity-50"
          >
            <Send className="w-4 h-4" />
            <span>Review & Send</span>
          </button>
        </div>
      </div>

      {testResult && (
        <div
          className={`p-3 rounded-lg text-xs flex items-center justify-between ${
            testResult.success
              ? "bg-emerald-50 border border-emerald-200 text-emerald-800"
              : "bg-red-50 border border-red-200 text-red-800"
          }`}
        >
          <div className="flex items-center gap-2">
            {testResult.success ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            ) : (
              <AlertCircle className="w-4 h-4 text-red-600" />
            )}
            <span>{testResult.message}</span>
          </div>
          <button onClick={() => setTestResult(null)} className="p-1 hover:opacity-75">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Grid: Left Column (Sender & Recipients), Right Column (Content Editor) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* LEFT COLUMN: Sender & Recipients Management */}
        <div className="lg:col-span-5 space-y-6">
          {/* Sender Identity Card */}
          <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-4">
            <h2 className="text-sm font-semibold text-slate-900 flex items-center justify-between">
              <span>Sender Identity</span>
              <span className="text-[11px] font-medium text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200">
                {profile?.settings?.deliveryMethod === "gmail_app_password" || profile?.settings?.gmail?.email
                  ? "Gmail App Password"
                  : "SMTP Dispatcher"}
              </span>
            </h2>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  From Name
                </label>
                <input
                  type="text"
                  value={fromName}
                  onChange={(e) => setFromName(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 focus:outline-none"
                  placeholder="e.g. MailForge Team"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  From Email
                </label>
                <input
                  type="email"
                  value={fromEmail}
                  onChange={(e) => setFromEmail(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 focus:outline-none"
                  placeholder="you@gmail.com"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Reply-To Address (Optional)
              </label>
              <input
                type="email"
                value={replyTo}
                onChange={(e) => setReplyTo(e.target.value)}
                className="w-full px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 focus:outline-none font-mono"
                placeholder="replies@example.com"
              />
            </div>

            {/* Engagement Tracking & Engine Indicator */}
            <div className="pt-3 border-t border-slate-100 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-700 flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-blue-600" />
                  Sending Engine:
                </span>
                <span className="text-[11px] font-medium text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200 flex items-center gap-1">
                  <Zap className="w-3 h-3 text-amber-500 fill-amber-500" />
                  {profile?.settings?.smtp?.host ? `Custom SMTP (${profile.settings.smtp.host}) · Unlimited` : "Self-Hosted SMTP · Unlimited Daily Sending"}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1 text-xs">
                <label className="flex items-center gap-2 cursor-pointer p-2 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 transition-colors">
                  <input
                    type="checkbox"
                    checked={trackOpens}
                    onChange={(e) => setTrackOpens(e.target.checked)}
                    className="rounded text-blue-600"
                  />
                  <div className="flex items-center gap-1.5">
                    <Eye className="w-3.5 h-3.5 text-blue-600" />
                    <span className="font-medium text-slate-800 text-[11px]">Track Email Opens (Pixel)</span>
                  </div>
                </label>

                <label className="flex items-center gap-2 cursor-pointer p-2 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 transition-colors">
                  <input
                    type="checkbox"
                    checked={trackClicks}
                    onChange={(e) => setTrackClicks(e.target.checked)}
                    className="rounded text-blue-600"
                  />
                  <div className="flex items-center gap-1.5">
                    <MousePointerClick className="w-3.5 h-3.5 text-indigo-600" />
                    <span className="font-medium text-slate-800 text-[11px]">Track Link Clicks (Proxy)</span>
                  </div>
                </label>
              </div>
            </div>
          </div>

          {/* Recipients Ingestion Card */}
          <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-slate-900">Recipient Management</h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  {recipients.length} total · {activeSelectedRecipients.length} selected
                </p>
              </div>

              {recipients.length > 0 && (
                <button
                  onClick={() => setRecipients([])}
                  className="text-xs text-red-600 hover:text-red-700 font-medium"
                >
                  Clear all
                </button>
              )}
            </div>

            {/* Input Method Switcher */}
            <div className="flex border-b border-slate-200 text-xs font-medium">
              <button
                onClick={() => setRecipientTab("paste")}
                className={`pb-2.5 px-3 border-b-2 transition-colors ${
                  recipientTab === "paste"
                    ? "border-blue-600 text-blue-600 font-semibold"
                    : "border-transparent text-slate-500 hover:text-slate-900"
                }`}
              >
                Paste / Manual
              </button>
              <button
                onClick={() => setRecipientTab("csv")}
                className={`pb-2.5 px-3 border-b-2 transition-colors ${
                  recipientTab === "csv"
                    ? "border-blue-600 text-blue-600 font-semibold"
                    : "border-transparent text-slate-500 hover:text-slate-900"
                }`}
              >
                Upload CSV
              </button>
              <button
                onClick={() => setRecipientTab("contacts")}
                className={`pb-2.5 px-3 border-b-2 transition-colors ${
                  recipientTab === "contacts"
                    ? "border-blue-600 text-blue-600 font-semibold"
                    : "border-transparent text-slate-500 hover:text-slate-900"
                }`}
              >
                Saved Contacts ({savedContacts.length})
              </button>
            </div>

            {/* Tab 1: Paste Emails */}
            {recipientTab === "paste" && (
              <div className="space-y-3">
                <textarea
                  rows={4}
                  value={rawPasteEmails}
                  onChange={(e) => setRawPasteEmails(e.target.value)}
                  placeholder="Paste emails separated by commas, spaces, or new lines...
alex@apextech.io, sarah@innovate.co
david@cloudscale.net"
                  className="w-full p-2.5 text-xs font-mono border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 focus:outline-none"
                />
                <button
                  onClick={handleParsePastedEmails}
                  disabled={!rawPasteEmails.trim()}
                  className="w-full py-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold rounded-lg shadow-sm transition-colors disabled:opacity-50"
                >
                  Parse & Add Emails
                </button>
              </div>
            )}

            {/* Tab 2: Upload CSV */}
            {recipientTab === "csv" && (
              <div className="space-y-3">
                <label className="border-2 border-dashed border-slate-300 hover:border-blue-500 rounded-xl p-6 flex flex-col items-center justify-center cursor-pointer transition-colors text-center bg-slate-50/50">
                  <Upload className="w-8 h-8 text-blue-600 mb-2" />
                  <span className="text-xs font-semibold text-slate-800">
                    Click or drag CSV file here
                  </span>
                  <span className="text-[11px] text-slate-500 mt-1">
                    Auto-detects email, firstName, lastName, company
                  </span>
                  <input
                    type="file"
                    accept=".csv"
                    onChange={handleCsvUpload}
                    className="hidden"
                  />
                </label>
              </div>
            )}

            {/* Tab 3: Select from Saved Contacts */}
            {recipientTab === "contacts" && (
              <div className="space-y-3">
                <div className="max-h-48 overflow-y-auto border border-slate-200 rounded-lg divide-y divide-slate-100 text-xs">
                  {savedContacts.length === 0 ? (
                    <div className="p-4 text-center text-slate-500">
                      No saved contacts available.
                    </div>
                  ) : (
                    savedContacts.map((c) => {
                      const isChecked = selectedContactIds.has(c.id);
                      return (
                        <label
                          key={c.id}
                          className={`flex items-center gap-2 p-2.5 hover:bg-slate-50 cursor-pointer ${
                            c.status !== "active" ? "opacity-50 bg-slate-50/50" : ""
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={isChecked}
                            disabled={c.status !== "active"}
                            onChange={(e) => {
                              const next = new Set(selectedContactIds);
                              if (e.target.checked) next.add(c.id);
                              else next.delete(c.id);
                              setSelectedContactIds(next);
                            }}
                            className="rounded text-blue-600 focus:ring-blue-500"
                          />
                          <div className="min-w-0 flex-1">
                            <p className="font-medium text-slate-900 truncate">
                              {c.firstName} {c.lastName} ({c.email})
                            </p>
                            <p className="text-[11px] text-slate-500">{c.company || "No company"}</p>
                          </div>
                          {c.status !== "active" && (
                            <span className="text-[10px] text-red-600 uppercase font-semibold">
                              Suppressed
                            </span>
                          )}
                        </label>
                      );
                    })
                  )}
                </div>

                <button
                  onClick={handleAddSelectedSavedContacts}
                  disabled={selectedContactIds.size === 0}
                  className="w-full py-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold rounded-lg shadow-sm transition-colors disabled:opacity-50"
                >
                  Add Selected ({selectedContactIds.size})
                </button>
              </div>
            )}

            {/* Validation & Deduplication Statistics */}
            {(duplicateCount > 0 || invalidAddresses.length > 0) && (
              <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs space-y-1">
                {duplicateCount > 0 && (
                  <p className="text-amber-800 font-medium">
                    ⚡ {duplicateCount} duplicate address(es) automatically removed.
                  </p>
                )}
                {invalidAddresses.length > 0 && (
                  <p className="text-red-700 font-medium">
                    ⚠️ {invalidAddresses.length} invalid email(s) ignored:{" "}
                    <span className="font-mono text-[11px]">{invalidAddresses.slice(0, 3).join(", ")}</span>
                  </p>
                )}
              </div>
            )}

            {/* Staged Recipients List */}
            {recipients.length > 0 && (
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs font-semibold text-slate-700">
                  <span>Staged Recipients ({recipients.length})</span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setRecipients(recipients.map((r) => ({ ...r, selected: true })))}
                      className="text-blue-600 hover:underline text-[11px]"
                    >
                      Select all
                    </button>
                    <span>·</span>
                    <button
                      onClick={() => setRecipients(recipients.map((r) => ({ ...r, selected: false })))}
                      className="text-slate-500 hover:underline text-[11px]"
                    >
                      Deselect all
                    </button>
                  </div>
                </div>

                <div className="max-h-60 overflow-y-auto border border-slate-200 rounded-lg divide-y divide-slate-100">
                  {recipients.map((r) => (
                    <div
                      key={r.id}
                      className="p-2.5 flex items-center justify-between hover:bg-slate-50 text-xs"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <input
                          type="checkbox"
                          checked={r.selected !== false}
                          onChange={() => handleToggleRecipient(r.id)}
                          className="rounded text-blue-600 focus:ring-blue-500"
                        />
                        <div className="min-w-0">
                          <p className="font-semibold text-slate-800 truncate">{r.email}</p>
                          {(r.firstName || r.company) && (
                            <p className="text-[11px] text-slate-500 truncate">
                              {[r.firstName, r.lastName].filter(Boolean).join(" ")}{" "}
                              {r.company && `· ${r.company}`}
                            </p>
                          )}
                        </div>
                      </div>

                      <button
                        onClick={() => handleRemoveRecipient(r.id)}
                        className="text-slate-400 hover:text-red-600 p-1"
                        title="Remove recipient"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* RIGHT COLUMN: Email Content & Rich Editor */}
        <div className="lg:col-span-7 space-y-6">
          <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-4">
            {/* Template Selector & Subject Line */}
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-900">Email Content</h2>
              <button
                onClick={() => setTemplateModalOpen(true)}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-blue-600 bg-blue-50 hover:bg-blue-100 rounded-lg border border-blue-200 transition-colors"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>Choose Template</span>
              </button>
            </div>

            {/* Subject input */}
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Subject Line
              </label>
              <div className="relative">
                <input
                  type="text"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  placeholder="e.g. Quick question regarding {{company}}'s developer platform"
                  className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 focus:outline-none"
                />
              </div>
            </div>

            {/* Personalization Variables Quick Insertion */}
            <div className="flex flex-wrap items-center gap-1.5 text-xs">
              <span className="text-slate-500 font-medium mr-1">Insert Variable:</span>
              {["firstName", "lastName", "company", "email"].map((tag) => (
                <button
                  key={tag}
                  type="button"
                  onClick={() => insertVariable(tag)}
                  className="px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-mono text-[11px] border border-slate-200 transition-colors"
                >
                  {`{{${tag}}}`}
                </button>
              ))}
            </div>

            {/* Editor Mode Tabs & Visual Toolbar */}
            <div className="border border-slate-200 rounded-lg overflow-hidden">
              <div className="bg-slate-50 border-b border-slate-200 px-3 py-2 flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => formatDoc("bold")}
                    className="p-1.5 rounded hover:bg-slate-200 text-slate-600"
                    title="Bold"
                  >
                    <Bold className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => formatDoc("italic")}
                    className="p-1.5 rounded hover:bg-slate-200 text-slate-600"
                    title="Italic"
                  >
                    <Italic className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => formatDoc("insertUnorderedList")}
                    className="p-1.5 rounded hover:bg-slate-200 text-slate-600"
                    title="Bullet List"
                  >
                    <List className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      const url = prompt("Enter link URL:");
                      if (url) formatDoc("createLink", url);
                    }}
                    className="p-1.5 rounded hover:bg-slate-200 text-slate-600"
                    title="Insert Link"
                  >
                    <LinkIcon className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="flex items-center bg-slate-200 p-0.5 rounded-md text-xs">
                  <button
                    type="button"
                    onClick={() => setEditorMode("visual")}
                    className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                      editorMode === "visual"
                        ? "bg-white text-slate-900 shadow-sm"
                        : "text-slate-600 hover:text-slate-900"
                    }`}
                  >
                    Visual
                  </button>
                  <button
                    type="button"
                    onClick={() => setEditorMode("html")}
                    className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                      editorMode === "html"
                        ? "bg-white text-slate-900 shadow-sm"
                        : "text-slate-600 hover:text-slate-900"
                    }`}
                  >
                    HTML Source
                  </button>
                </div>
              </div>

              {/* Editor Workspace */}
              {editorMode === "visual" ? (
                <div
                  ref={editorRef}
                  contentEditable
                  onInput={(e) => setHtmlContent(e.currentTarget.innerHTML)}
                  className="min-h-[360px] p-4 text-sm text-slate-900 focus:outline-none overflow-y-auto font-sans"
                  style={{ minHeight: "360px" }}
                />
              ) : (
                <textarea
                  rows={16}
                  value={htmlContent}
                  onChange={(e) => setHtmlContent(e.target.value)}
                  className="w-full p-4 font-mono text-xs text-slate-900 focus:outline-none resize-y"
                  style={{ minHeight: "360px" }}
                />
              )}
            </div>

            {/* Plain Text Fallback Section */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-semibold text-slate-700">
                  Plain-Text Fallback
                </label>
                <button
                  type="button"
                  onClick={() => setTextContent(htmlToPlainText(htmlContent))}
                  className="text-[11px] text-blue-600 hover:underline"
                >
                  Generate from HTML
                </button>
              </div>
              <textarea
                rows={3}
                value={textContent}
                onChange={(e) => setTextContent(e.target.value)}
                placeholder="Plain text version for text-only email clients..."
                className="w-full p-2.5 text-xs font-mono border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 focus:outline-none"
              />
            </div>
          </div>
        </div>
      </div>

      {/* MODAL 1: Choose Template Modal */}
      {templateModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-xl shadow-xl border border-slate-200 max-w-2xl w-full p-6 space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <h3 className="text-base font-bold text-slate-900">Choose an Email Template</h3>
              <button onClick={() => setTemplateModalOpen(false)} className="p-1 text-slate-400 hover:text-slate-600">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {availableTemplates.map((tmpl) => (
                <div
                  key={tmpl.id}
                  onClick={() => {
                    setSubject(tmpl.subject);
                    setHtmlContent(tmpl.htmlContent);
                    setTextContent(tmpl.textContent || htmlToPlainText(tmpl.htmlContent));
                    setTemplateModalOpen(false);
                  }}
                  className="p-4 border border-slate-200 rounded-xl hover:border-blue-500 hover:shadow-sm cursor-pointer transition-all bg-white"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-bold text-slate-900">{tmpl.name}</span>
                    <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded bg-slate-100 text-slate-600">
                      {tmpl.category}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 line-clamp-2 mt-1">{tmpl.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* MODAL 2: Interactive Live Preview Modal */}
      {previewOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-xl shadow-xl border border-slate-200 max-w-3xl w-full p-6 space-y-4 max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div>
                <h3 className="text-base font-bold text-slate-900">Email Preview & Personalization Check</h3>
                <p className="text-xs text-slate-500">
                  Simulating message as rendered for recipient {previewRecipientIndex + 1} of{" "}
                  {Math.max(1, activeSelectedRecipients.length)}
                </p>
              </div>
              <button onClick={() => setPreviewOpen(false)} className="p-1 text-slate-400 hover:text-slate-600">
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Recipient switcher */}
            {activeSelectedRecipients.length > 1 && (
              <div className="flex items-center gap-2 text-xs">
                <span className="text-slate-500">Preview as:</span>
                <select
                  value={previewRecipientIndex}
                  onChange={(e) => setPreviewRecipientIndex(Number(e.target.value))}
                  className="px-2 py-1 border border-slate-300 rounded text-xs"
                >
                  {activeSelectedRecipients.slice(0, 10).map((r, i) => (
                    <option key={r.id} value={i}>
                      {r.email} ({r.firstName || "No name"})
                    </option>
                  ))}
                </select>
              </div>
            )}

            {/* Email Header Metadata */}
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs space-y-1">
              <div>
                <span className="font-semibold text-slate-600">From: </span>
                <span className="text-slate-900 font-mono">
                  "{fromName}" &lt;{fromEmail}&gt;
                </span>
              </div>
              <div>
                <span className="font-semibold text-slate-600">To: </span>
                <span className="text-slate-900 font-mono">{previewTarget.email}</span>
              </div>
              <div>
                <span className="font-semibold text-slate-600">Subject: </span>
                <span className="text-slate-900 font-medium">{previewSubject}</span>
              </div>
            </div>

            {/* Rendered HTML Body */}
            <div className="flex-1 overflow-y-auto border border-slate-200 rounded-lg p-4 bg-white">
              <div
                dangerouslySetInnerHTML={{ __html: previewHtml }}
                className="font-sans"
              />
            </div>
          </div>
        </div>
      )}

      {/* MODAL 3: Confirm & Schedule Dispatch Modal */}
      {confirmSendOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-xl shadow-xl border border-slate-200 max-w-md w-full p-6 space-y-4">
            <h3 className="text-lg font-bold text-slate-900">Confirm Campaign Dispatch</h3>

            <div className="p-4 bg-blue-50 border border-blue-200 rounded-xl text-xs space-y-2 text-blue-900">
              <div className="flex justify-between">
                <span className="text-blue-700">Recipients:</span>
                <span className="font-bold">{activeSelectedRecipients.length} addresses</span>
              </div>
              <div className="flex justify-between">
                <span className="text-blue-700">Sender Identity:</span>
                <span className="font-medium font-mono">{fromEmail}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-blue-700">Delivery Service:</span>
                <span className="font-semibold text-emerald-800">
                  {profile?.settings?.smtp?.host ? `Custom SMTP (${profile.settings.smtp.host}) · Unlimited Sending` : "Self-Hosted SMTP · Unlimited Sending"}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-blue-700">Engagement Tracking:</span>
                <span className="font-medium">
                  {trackOpens ? "Opens (Pixel)" : ""} {trackOpens && trackClicks ? "& " : ""}{trackClicks ? "Clicks (Redirect)" : ""}{!trackOpens && !trackClicks ? "Disabled" : " Active"}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-blue-700">Suppression Check:</span>
                <span className="font-medium text-emerald-700">Enabled</span>
              </div>
            </div>

            {/* Schedule Option */}
            <div className="pt-2 border-t border-slate-100">
              <label className="flex items-center gap-2 text-xs font-semibold text-slate-800 cursor-pointer mb-2">
                <input
                  type="checkbox"
                  checked={scheduleMode}
                  onChange={(e) => setScheduleMode(e.target.checked)}
                  className="rounded text-blue-600"
                />
                <span>Schedule for a future date & time</span>
              </label>

              {scheduleMode && (
                <input
                  type="datetime-local"
                  value={scheduleDateTime}
                  onChange={(e) => setScheduleDateTime(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500"
                />
              )}
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setConfirmSendOpen(false)}
                className="px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-100 rounded-lg"
              >
                Cancel
              </button>
              <button
                onClick={handleExecuteSend}
                className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg shadow-sm"
              >
                {scheduleMode ? "Schedule Campaign" : "Send Now"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 4: Real-time Dispatch Progress Modal */}
      {isProcessing && sendProgress && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-xl shadow-xl border border-slate-200 max-w-md w-full p-6 text-center space-y-4">
            <RefreshCw className="w-10 h-10 text-blue-600 animate-spin mx-auto" />
            <h3 className="text-base font-bold text-slate-900">Dispatching Bulk Campaign</h3>
            <p className="text-xs text-slate-500">{sendProgress.statusText}</p>

            {/* Progress Bar */}
            <div className="w-full bg-slate-100 rounded-full h-3 overflow-hidden">
              <div
                className="bg-blue-600 h-full transition-all duration-300 rounded-full"
                style={{
                  width: `${
                    sendProgress.total > 0
                      ? ((sendProgress.sent + sendProgress.failed) / sendProgress.total) * 100
                      : 0
                  }%`,
                }}
              />
            </div>

            <div className="flex justify-between text-xs text-slate-600 pt-1">
              <span>{sendProgress.sent} dispatched</span>
              <span>{sendProgress.failed} failed</span>
              <span>{sendProgress.total} total</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
