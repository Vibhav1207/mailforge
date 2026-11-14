"use client";

import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { motion, AnimatePresence } from "motion/react";
import Papa from "papaparse";
import { useAuth } from "@/context/auth-context";
import {
  getContacts,
  getTemplates,
  saveCampaign,
} from "@/lib/store/db-service";
import { apiFetch } from "@/lib/api-client";
import { Contact, EmailTemplate, Campaign, EmailAttachment } from "@/types";
import {
  parseSpreadsheetFile,
  SpreadsheetColumnDetection,
  sanitizeFieldName,
} from "@/lib/spreadsheet";
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
  FileSpreadsheet,
  CheckCheck,
  Paperclip,
} from "lucide-react";

interface RecipientItem {
  id: string;
  email: string;
  name?: string;
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
  const [campaignName, setCampaignName] = useState("Campaign " + new Date().toLocaleDateString());
  const [subject, setSubject] = useState("");
  const [fromName, setFromName] = useState(profile?.settings?.defaultFromName || "Postvane Team");
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

  // Spreadsheet Upload State (.xlsx, .xls, .csv)
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const [detectedColumns, setDetectedColumns] = useState<SpreadsheetColumnDetection | null>(null);
  const [discoveredCustomFields, setDiscoveredCustomFields] = useState<string[]>([]);
  const [isParsingSpreadsheet, setIsParsingSpreadsheet] = useState(false);
  const [spreadsheetError, setSpreadsheetError] = useState<string | null>(null);

  // Saved Contacts Picker
  const [savedContacts, setSavedContacts] = useState<Contact[]>([]);
  const [selectedContactIds, setSelectedContactIds] = useState<Set<string>>(new Set());

  // Templates
  const [availableTemplates, setAvailableTemplates] = useState<EmailTemplate[]>([]);
  const [templateModalOpen, setTemplateModalOpen] = useState(false);

  // Attachments State (PDFs & Documents)
  const [attachments, setAttachments] = useState<EmailAttachment[]>([]);
  const [attachmentError, setAttachmentError] = useState<string | null>(null);

  // Preview & Test State
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewRecipientIndex, setPreviewRecipientIndex] = useState(0);
  const [sendingTest, setSendingTest] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  // Confirm Dispatch & Scheduling Modal
  const [confirmSendOpen, setConfirmSendOpen] = useState(false);
  const [scheduleMode, setScheduleMode] = useState(false);
  const [scheduleDateTime, setScheduleDateTime] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const [sendProgress, setSendProgress] = useState<{
    sent: number;
    failed: number;
    total: number;
    statusText: string;
  } | null>(null);

  // Draft Auto-saving State
  const [lastSaved, setLastSaved] = useState<string | null>(null);
  const [savingDraft, setSavingDraft] = useState(false);

  const editorRef = useRef<HTMLDivElement>(null);

  // Load Contacts and Templates on mount
  useEffect(() => {
    if (!userId) return;
    const fetchData = async () => {
      try {
        const [contacts, tmpls] = await Promise.all([
          getContacts(userId),
          getTemplates(userId),
        ]);
        setSavedContacts(contacts.filter((c) => c.status === "active"));
        setAvailableTemplates(tmpls);
      } catch (e) {
        console.error("Load initial composer data error:", e);
      }
    };
    fetchData();
  }, [userId]);

  // Synchronize visual editor contents
  useEffect(() => {
    if (editorRef.current && editorMode === "visual" && editorRef.current.innerHTML !== htmlContent) {
      editorRef.current.innerHTML = htmlContent;
    }
  }, [htmlContent, editorMode]);

  // Parse pasted raw emails
  const handleParsePastedEmails = () => {
    if (!rawPasteEmails.trim()) return;
    const parsed = parseEmailList(rawPasteEmails);
    const existing = new Set(recipients.map((r) => r.email.toLowerCase()));

    const nextItems: RecipientItem[] = [];
    let dupes = 0;

    for (const validEmail of parsed.valid) {
      const emailLower = validEmail.toLowerCase();
      if (existing.has(emailLower)) {
        dupes++;
      } else {
        existing.add(emailLower);
        nextItems.push({
          id: `rec_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
          email: validEmail,
          selected: true,
        });
      }
    }

    setDuplicateCount((prev) => prev + dupes);
    setInvalidAddresses(parsed.invalid);
    setRecipients((prev) => [...prev, ...nextItems]);
    setRawPasteEmails("");
  };

  // Parse uploaded spreadsheet (.xlsx, .xls, .csv)
  const handleSpreadsheetUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsParsingSpreadsheet(true);
    setSpreadsheetError(null);
    setUploadedFileName(file.name);

    try {
      const result = await parseSpreadsheetFile(file);
      setDetectedColumns(result.detection);
      setDiscoveredCustomFields(result.detection.customColumns);

      const existingEmails = new Set(recipients.map((r) => r.email.toLowerCase()));
      const validItems: RecipientItem[] = [];
      let duplicates = result.duplicateCount || 0;

      for (const item of result.recipients) {
        const lower = item.email.toLowerCase();
        if (existingEmails.has(lower)) {
          duplicates++;
        } else {
          existingEmails.add(lower);
          validItems.push({
            id: item.id || `rec_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
            email: item.email,
            firstName: item.firstName,
            lastName: item.lastName,
            name: item.name,
            company: item.company,
            customFields: item.customFields,
            selected: true,
          });
        }
      }

      setRecipients((prev) => [...prev, ...validItems]);
      setInvalidAddresses(result.invalidEmails || []);
      setDuplicateCount((prev) => prev + duplicates);
    } catch (err: any) {
      setSpreadsheetError(err.message || "Failed to parse file");
    } finally {
      setIsParsingSpreadsheet(false);
      e.target.value = "";
    }
  };

  // Add saved contacts selected from library
  const handleAddSelectedSavedContacts = () => {
    const existingEmails = new Set(recipients.map((r) => r.email.toLowerCase()));
    const itemsToAdd: RecipientItem[] = [];
    let dupes = 0;

    for (const c of savedContacts) {
      if (selectedContactIds.has(c.id)) {
        const lower = c.email.toLowerCase();
        if (existingEmails.has(lower)) {
          dupes++;
        } else {
          existingEmails.add(lower);
          itemsToAdd.push({
            id: `rec_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
            email: c.email,
            firstName: c.firstName,
            lastName: c.lastName,
            company: c.company,
            customFields: c.customFields,
            selected: true,
          });
        }
      }
    }

    setDuplicateCount((prev) => prev + dupes);
    setRecipients((prev) => [...prev, ...itemsToAdd]);
    setSelectedContactIds(new Set());
  };

  // Attachment handler for PDF & Documents
  const handleAttachmentChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;
    setAttachmentError(null);

    const maxFileSize = 4 * 1024 * 1024; // 4MB
    const maxAttachments = 5;

    if (attachments.length + files.length > maxAttachments) {
      setAttachmentError(`Maximum ${maxAttachments} attachments allowed per campaign.`);
      return;
    }

    const newAttachments: EmailAttachment[] = [];
    let filesProcessed = 0;
    const filesToProcess = Array.from(files);

    filesToProcess.forEach((file) => {
      if (file.size > maxFileSize) {
        setAttachmentError(`File "${file.name}" exceeds the 4MB limit.`);
        return;
      }

      const reader = new FileReader();
      reader.onload = (event) => {
        const result = event.target?.result as string;
        if (result) {
          const base64Data = result.split(",")[1];
          newAttachments.push({
            id: `att_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
            filename: file.name,
            contentType: file.type || "application/octet-stream",
            contentBase64: base64Data,
            size: file.size,
          });
        }
        filesProcessed++;
        if (filesProcessed === filesToProcess.length) {
          setAttachments((prev) => [...prev, ...newAttachments]);
        }
      };
      reader.onerror = () => {
        setAttachmentError(`Failed to read file "${file.name}".`);
      };
      reader.readAsDataURL(file);
    });

    e.target.value = "";
  };

  const removeAttachment = (idOrIndex: string | number) => {
    setAttachments((prev) =>
      prev.filter((item, idx) => (typeof idOrIndex === "string" ? item.id !== idOrIndex : idx !== idOrIndex))
    );
  };

  const handleRemoveRecipient = (id: string) => {
    setRecipients(recipients.filter((r) => r.id !== id));
  };

  const handleToggleRecipient = (id: string) => {
    setRecipients(
      recipients.map((r) => (r.id === id ? { ...r, selected: !r.selected } : r))
    );
  };

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

  const formatDoc = (cmd: string, val: string | undefined = undefined) => {
    if (editorMode === "visual" && editorRef.current) {
      editorRef.current.focus();
      document.execCommand(cmd, false, val);
      setHtmlContent(editorRef.current.innerHTML);
    }
  };

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
          attachments: attachments.length ? attachments : undefined,
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

  const activeSelectedRecipients = recipients.filter((r) => r.selected !== false);

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
        attachments: attachments.length ? attachments : undefined,
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
      router.push(`/dashboard/campaigns`);
      return;
    }

    try {
      const initialCampaign: Campaign = {
        id: campaignId,
        userId,
        name: campaignName,
        subject,
        fromName,
        fromEmail,
        replyTo,
        htmlContent,
        textContent: textContent || htmlToPlainText(htmlContent),
        attachments: attachments.length ? attachments : undefined,
        recipientCount: activeSelectedRecipients.length,
        status: "sending",
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

      await saveCampaign(initialCampaign);

      const res = await apiFetch("/api/campaigns/send-bulk", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          campaign: initialCampaign,
          recipients: activeSelectedRecipients.map((r) => ({
            id: r.id,
            email: r.email,
            firstName: r.firstName,
            lastName: r.lastName,
            name: r.name,
            company: r.company,
            customFields: r.customFields,
          })),
          trackOpens,
          trackClicks,
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to process campaign");

      setIsProcessing(false);
      router.push(`/dashboard/campaigns/${campaignId}`);
    } catch (err: any) {
      alert(err.message || "Failed to dispatch campaign");
      setIsProcessing(false);
    }
  };

  const previewTarget = activeSelectedRecipients[previewRecipientIndex] || {
    email: "sarah.connor@cyberdyne.io",
    firstName: "Sarah",
    lastName: "Connor",
    name: "Sarah Connor",
    company: "Cyberdyne Systems",
  };

  const previewHtml = interpolateVariables(htmlContent, {
    ...previewTarget.customFields,
    name: previewTarget.name || [previewTarget.firstName, previewTarget.lastName].filter(Boolean).join(" "),
    firstName: previewTarget.firstName,
    lastName: previewTarget.lastName,
    company: previewTarget.company,
    email: previewTarget.email,
    fromName,
    unsubscribeUrl: `${typeof window !== "undefined" ? window.location.origin : ""}/unsubscribe`,
  });

  const previewSubject = interpolateVariables(subject, {
    ...previewTarget.customFields,
    name: previewTarget.name || [previewTarget.firstName, previewTarget.lastName].filter(Boolean).join(" "),
    firstName: previewTarget.firstName,
    lastName: previewTarget.lastName,
    company: previewTarget.company,
    email: previewTarget.email,
    fromName,
    unsubscribeUrl: `${typeof window !== "undefined" ? window.location.origin : ""}/unsubscribe`,
  });

  return (
    <div className="space-y-6 pb-12">
      {/* Header & Campaign Name Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-[#262A2E] pb-5">
        <div className="flex-1 max-w-xl">
          <input
            type="text"
            value={campaignName}
            onChange={(e) => setCampaignName(e.target.value)}
            className="text-2xl font-medium tracking-tight text-white bg-transparent border-0 border-b border-transparent hover:border-[#262A2E] focus:border-white focus:ring-0 px-0 py-1 w-full transition-colors font-sans"
            placeholder="Campaign Name"
          />
          <div className="flex items-center gap-3 mt-1 text-xs text-zinc-500 font-mono">
            <span className="flex items-center gap-1">
              <Save className="w-3.5 h-3.5" />
              {savingDraft
                ? "Saving draft..."
                : lastSaved
                ? `Saved as draft at ${lastSaved}`
                : "Auto-save active"}
            </span>
            <span>•</span>
            <span className="text-zinc-400">{activeSelectedRecipients.length} recipients staged</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <motion.button
            whileHover={{ y: -1 }}
            whileTap={{ scale: 0.97 }}
            transition={{ duration: 0.18 }}
            onClick={() => setPreviewOpen(true)}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium text-zinc-300 bg-[#111315] border border-[#262A2E] rounded-lg hover:border-zinc-500 hover:text-white transition-colors"
          >
            <Eye className="w-3.5 h-3.5 text-zinc-400" />
            <span>Preview</span>
          </motion.button>

          <motion.button
            whileHover={{ y: -1 }}
            whileTap={{ scale: 0.97 }}
            transition={{ duration: 0.18 }}
            onClick={handleSendTestEmail}
            disabled={sendingTest || !subject || !htmlContent}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium text-zinc-300 bg-[#111315] border border-[#262A2E] rounded-lg hover:border-zinc-500 hover:text-white transition-colors disabled:opacity-40"
          >
            <Mail className="w-3.5 h-3.5 text-zinc-400" />
            <span>{sendingTest ? "Sending..." : "Send Test"}</span>
          </motion.button>

          <motion.button
            whileHover={{ y: -1 }}
            whileTap={{ scale: 0.97 }}
            transition={{ duration: 0.18 }}
            onClick={() => setConfirmSendOpen(true)}
            disabled={activeSelectedRecipients.length === 0 || !subject.trim() || !htmlContent.trim()}
            className="inline-flex items-center gap-2 px-4 py-1.5 text-xs font-medium text-black bg-white hover:bg-zinc-200 rounded-lg transition-colors disabled:opacity-40 shadow-sm"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Review & Send</span>
          </motion.button>
        </div>
      </div>

      {testResult && (
        <div
          className={`p-3 rounded-lg text-xs flex items-center justify-between border ${
            testResult.success
              ? "bg-emerald-950/40 border-emerald-500/30 text-emerald-400 font-mono"
              : "bg-red-950/40 border-red-500/30 text-red-400 font-mono"
          }`}
        >
          <div className="flex items-center gap-2">
            {testResult.success ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <AlertCircle className="w-4 h-4 text-red-400" />
            )}
            <span>{testResult.message}</span>
          </div>
          <button onClick={() => setTestResult(null)} className="p-1 hover:opacity-75">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Grid: Left Column (Sender & Recipients), Right Column (Content Editor) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* LEFT COLUMN: Sender & Recipients Management */}
        <div className="lg:col-span-5 space-y-6">
          {/* Sender Identity Card */}
          <div className="bg-[#111315] p-5 rounded-xl border border-[#262A2E] space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-mono uppercase tracking-wider text-zinc-400">Sender Identity</h2>
              <span className="text-[10px] font-mono text-zinc-400 bg-[#171A1D] px-2 py-0.5 rounded border border-[#262A2E]">
                {profile?.settings?.deliveryMethod === "gmail_app_password" || profile?.settings?.gmail?.email
                  ? "GMAIL APP PASSWORD"
                  : "SMTP DISPATCHER"}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                  From Name
                </label>
                <input
                  type="text"
                  value={fromName}
                  onChange={(e) => setFromName(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none"
                  placeholder="e.g. Postvane Team"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                  From Email
                </label>
                <input
                  type="email"
                  value={fromEmail}
                  onChange={(e) => setFromEmail(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs bg-[#171A1D] border border-[#262A2E] text-white font-mono rounded-lg focus:border-zinc-500 focus:outline-none"
                  placeholder="you@gmail.com"
                />
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                Reply-To Address (Optional)
              </label>
              <input
                type="email"
                value={replyTo}
                onChange={(e) => setReplyTo(e.target.value)}
                className="w-full px-3 py-1.5 text-xs bg-[#171A1D] border border-[#262A2E] text-white font-mono rounded-lg focus:border-zinc-500 focus:outline-none"
                placeholder="replies@example.com"
              />
            </div>

            {/* Engagement Tracking & Engine Indicator */}
            <div className="pt-3 border-t border-[#1C2024] space-y-2.5">
              <div className="flex items-center justify-between text-xs">
                <span className="text-zinc-400 font-mono text-[11px] flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-zinc-400" />
                  Delivery Transport:
                </span>
                <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/40 border border-emerald-500/30 px-2 py-0.5 rounded flex items-center gap-1">
                  <Zap className="w-3 h-3 text-emerald-400" />
                  {profile?.settings?.smtp?.host ? `SMTP (${profile.settings.smtp.host})` : "Direct SMTP Relay"}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1 text-xs">
                <label className="flex items-center gap-2 cursor-pointer p-2 rounded-lg bg-[#171A1D] hover:bg-[#1D2125] border border-[#262A2E] transition-colors">
                  <input
                    type="checkbox"
                    checked={trackOpens}
                    onChange={(e) => setTrackOpens(e.target.checked)}
                    className="rounded bg-[#111315] border-[#262A2E] text-white focus:ring-0"
                  />
                  <div className="flex items-center gap-1.5">
                    <Eye className="w-3.5 h-3.5 text-zinc-400" />
                    <span className="text-zinc-300 font-mono text-[11px]">Track Opens (Pixel)</span>
                  </div>
                </label>

                <label className="flex items-center gap-2 cursor-pointer p-2 rounded-lg bg-[#171A1D] hover:bg-[#1D2125] border border-[#262A2E] transition-colors">
                  <input
                    type="checkbox"
                    checked={trackClicks}
                    onChange={(e) => setTrackClicks(e.target.checked)}
                    className="rounded bg-[#111315] border-[#262A2E] text-white focus:ring-0"
                  />
                  <div className="flex items-center gap-1.5">
                    <MousePointerClick className="w-3.5 h-3.5 text-zinc-400" />
                    <span className="text-zinc-300 font-mono text-[11px]">Track Clicks (Proxy)</span>
                  </div>
                </label>
              </div>
            </div>
          </div>

          {/* Recipients Ingestion Card */}
          <div className="bg-[#111315] p-5 rounded-xl border border-[#262A2E] space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xs font-mono uppercase tracking-wider text-zinc-400">Recipient Management</h2>
                <p className="text-xs text-zinc-500 font-mono mt-0.5">
                  {recipients.length} staged · {activeSelectedRecipients.length} active
                </p>
              </div>

              {recipients.length > 0 && (
                <button
                  onClick={() => setRecipients([])}
                  className="text-xs text-red-400 hover:text-red-300 font-mono"
                >
                  Clear all
                </button>
              )}
            </div>

            {/* Input Method Switcher */}
            <div className="flex border-b border-[#262A2E] text-xs font-mono">
              <button
                onClick={() => setRecipientTab("paste")}
                className={`pb-2.5 px-3 border-b-2 transition-colors ${
                  recipientTab === "paste"
                    ? "border-white text-white font-medium"
                    : "border-transparent text-zinc-500 hover:text-zinc-300"
                }`}
              >
                Paste / Manual
              </button>
              <button
                onClick={() => setRecipientTab("csv")}
                className={`pb-2.5 px-3 border-b-2 transition-colors flex items-center gap-1.5 ${
                  recipientTab === "csv"
                    ? "border-white text-white font-medium"
                    : "border-transparent text-zinc-500 hover:text-zinc-300"
                }`}
              >
                <FileSpreadsheet className="w-3.5 h-3.5" />
                <span>Upload Excel / CSV</span>
              </button>
              <button
                onClick={() => setRecipientTab("contacts")}
                className={`pb-2.5 px-3 border-b-2 transition-colors ${
                  recipientTab === "contacts"
                    ? "border-white text-white font-medium"
                    : "border-transparent text-zinc-500 hover:text-zinc-300"
                }`}
              >
                Contacts ({savedContacts.length})
              </button>
            </div>

            {/* Tab 1: Paste Emails */}
            {recipientTab === "paste" && (
              <div className="space-y-3">
                <textarea
                  rows={4}
                  value={rawPasteEmails}
                  onChange={(e) => setRawPasteEmails(e.target.value)}
                  placeholder="Paste emails separated by commas, spaces, or new lines...&#10;alex@apextech.io, sarah@innovate.co&#10;david@cloudscale.net"
                  className="w-full p-2.5 text-xs font-mono bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none"
                />
                <button
                  onClick={handleParsePastedEmails}
                  disabled={!rawPasteEmails.trim()}
                  className="w-full py-2 bg-white hover:bg-zinc-200 text-black text-xs font-medium rounded-lg transition-colors disabled:opacity-40"
                >
                  Parse & Add Emails
                </button>
              </div>
            )}

            {/* Tab 2: Upload Excel / CSV */}
            {recipientTab === "csv" && (
              <div className="space-y-4">
                <label className="border border-dashed border-[#262A2E] hover:border-zinc-500 bg-[#171A1D]/40 hover:bg-[#171A1D] rounded-xl p-5 flex flex-col items-center justify-center cursor-pointer transition-all text-center group">
                  <div className="w-10 h-10 rounded-full bg-[#111315] border border-[#262A2E] flex items-center justify-center mb-2.5 text-zinc-400 group-hover:text-white transition-colors">
                    {isParsingSpreadsheet ? (
                      <RefreshCw className="w-4 h-4 animate-spin text-white" />
                    ) : (
                      <FileSpreadsheet className="w-4 h-4" />
                    )}
                  </div>
                  <span className="text-xs font-medium text-white">
                    {isParsingSpreadsheet ? "Analyzing columns..." : "Click to upload Excel (.xlsx) or CSV"}
                  </span>
                  <span className="text-[11px] text-zinc-500 mt-1 max-w-xs font-mono">
                    Auto-detects emails, names, companies, and custom fields
                  </span>
                  <input
                    type="file"
                    accept=".xlsx,.xls,.csv,.tsv"
                    disabled={isParsingSpreadsheet}
                    onChange={handleSpreadsheetUpload}
                    className="hidden"
                  />
                </label>

                {spreadsheetError && (
                  <div className="p-3 bg-red-950/40 border border-red-500/30 rounded-lg text-xs text-red-400 flex items-center gap-2 font-mono">
                    <AlertCircle className="w-4 h-4 shrink-0" />
                    <span>{spreadsheetError}</span>
                  </div>
                )}

                {uploadedFileName && detectedColumns && (
                  <div className="p-3.5 bg-[#171A1D] border border-[#262A2E] rounded-xl text-xs space-y-2.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-white font-medium">
                        <FileSpreadsheet className="w-4 h-4 text-emerald-400" />
                        <span className="truncate max-w-[200px]">{uploadedFileName}</span>
                      </div>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950/50 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                        <CheckCheck className="w-3 h-3" /> Auto-Mapped
                      </span>
                    </div>

                    <div className="pt-2 border-t border-[#262A2E] grid grid-cols-2 gap-2 text-[11px] font-mono">
                      <div>
                        <span className="text-zinc-500">Email: </span>
                        <span className="text-zinc-200">{detectedColumns.emailColumn || "Detected"}</span>
                      </div>
                      <div>
                        <span className="text-zinc-500">Name: </span>
                        <span className="text-zinc-200">{detectedColumns.nameColumn || detectedColumns.firstNameColumn || "Not specified"}</span>
                      </div>
                    </div>

                    {detectedColumns.customColumns.length > 0 && (
                      <div className="pt-2 border-t border-[#262A2E]">
                        <span className="text-zinc-500 block text-[11px] font-mono mb-1">
                          Mapped Variables:
                        </span>
                        <div className="flex flex-wrap gap-1">
                          {detectedColumns.customColumns.map((col) => (
                            <span
                              key={col}
                              className="px-1.5 py-0.5 rounded bg-[#111315] border border-[#262A2E] text-zinc-300 font-mono text-[10px]"
                            >
                              {col}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Tab 3: Select from Saved Contacts */}
            {recipientTab === "contacts" && (
              <div className="space-y-3">
                <div className="max-h-48 overflow-y-auto border border-[#262A2E] rounded-lg divide-y divide-[#1C2024] text-xs">
                  {savedContacts.length === 0 ? (
                    <div className="p-4 text-center text-zinc-500 font-mono">
                      No saved contacts available
                    </div>
                  ) : (
                    savedContacts.map((c) => {
                      const isChecked = selectedContactIds.has(c.id);
                      return (
                        <label
                          key={c.id}
                          className={`flex items-center gap-2 p-2.5 hover:bg-[#171A1D] cursor-pointer ${
                            c.status !== "active" ? "opacity-50" : ""
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
                            className="rounded bg-[#111315] border-[#262A2E] text-white focus:ring-0"
                          />
                          <div className="min-w-0 flex-1">
                            <p className="font-medium text-white truncate">
                              {c.firstName} {c.lastName} ({c.email})
                            </p>
                            <p className="text-[11px] text-zinc-500 font-mono">{c.company || "No company"}</p>
                          </div>
                        </label>
                      );
                    })
                  )}
                </div>

                <button
                  onClick={handleAddSelectedSavedContacts}
                  disabled={selectedContactIds.size === 0}
                  className="w-full py-2 bg-white hover:bg-zinc-200 text-black text-xs font-medium rounded-lg transition-colors disabled:opacity-40"
                >
                  Add Selected ({selectedContactIds.size})
                </button>
              </div>
            )}

            {/* Validation & Deduplication Statistics */}
            {(duplicateCount > 0 || invalidAddresses.length > 0) && (
              <div className="p-3 bg-[#171A1D] border border-[#262A2E] rounded-lg text-xs space-y-1 font-mono">
                {duplicateCount > 0 && (
                  <p className="text-amber-400">
                    ⚡ {duplicateCount} duplicates automatically deduped.
                  </p>
                )}
                {invalidAddresses.length > 0 && (
                  <p className="text-red-400">
                    ⚠️ {invalidAddresses.length} invalid email(s) ignored:{" "}
                    <span>{invalidAddresses.slice(0, 3).join(", ")}</span>
                  </p>
                )}
              </div>
            )}

            {/* Staged Recipients List */}
            {recipients.length > 0 && (
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs font-mono text-zinc-400">
                  <span>Staged ({recipients.length})</span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setRecipients(recipients.map((r) => ({ ...r, selected: true })))}
                      className="text-zinc-300 hover:text-white"
                    >
                      Select all
                    </button>
                    <span>·</span>
                    <button
                      onClick={() => setRecipients(recipients.map((r) => ({ ...r, selected: false })))}
                      className="text-zinc-500 hover:text-zinc-300"
                    >
                      Deselect
                    </button>
                  </div>
                </div>

                <div className="max-h-60 overflow-y-auto border border-[#262A2E] rounded-lg divide-y divide-[#1C2024]">
                  {recipients.map((r) => (
                    <div
                      key={r.id}
                      className="p-2.5 flex items-center justify-between hover:bg-[#171A1D] text-xs transition-colors"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <input
                          type="checkbox"
                          checked={r.selected !== false}
                          onChange={() => handleToggleRecipient(r.id)}
                          className="rounded bg-[#111315] border-[#262A2E] text-white focus:ring-0"
                        />
                        <div className="min-w-0">
                          <p className="font-mono text-white truncate text-[11px]">{r.email}</p>
                          {(r.name || r.firstName || r.company) && (
                            <p className="text-[10px] text-zinc-500 truncate">
                              {r.name || [r.firstName, r.lastName].filter(Boolean).join(" ")}{" "}
                              {r.company && `· ${r.company}`}
                            </p>
                          )}
                        </div>
                      </div>

                      <button
                        onClick={() => handleRemoveRecipient(r.id)}
                        className="text-zinc-500 hover:text-red-400 p-1"
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
          <div className="bg-[#111315] p-5 rounded-xl border border-[#262A2E] space-y-4">
            {/* Template Selector & Subject Line */}
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-mono uppercase tracking-wider text-zinc-400">Email Content</h2>
              <button
                onClick={() => setTemplateModalOpen(true)}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono text-zinc-300 bg-[#171A1D] hover:bg-[#1D2125] rounded-lg border border-[#262A2E] transition-colors"
              >
                <Sparkles className="w-3.5 h-3.5 text-zinc-400" />
                <span>Choose Template</span>
              </button>
            </div>

            {/* Subject input */}
            <div>
              <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                Subject Line
              </label>
              <input
                type="text"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                placeholder="e.g. Update regarding {{company}}'s developer platform"
                className="w-full px-3 py-2 text-sm bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none"
              />
            </div>

            {/* Personalization Variables Quick Insertion */}
            <div className="flex flex-wrap items-center gap-1.5 text-xs">
              <span className="text-zinc-500 font-mono text-[11px] mr-1">Variables:</span>
              {Array.from(new Set(["name", "firstName", "lastName", "company", "email", ...discoveredCustomFields])).map((tag) => (
                <button
                  key={tag}
                  type="button"
                  onClick={() => insertVariable(tag)}
                  className="px-2 py-0.5 rounded font-mono text-[11px] bg-[#171A1D] hover:bg-[#1D2125] text-zinc-300 border border-[#262A2E] transition-colors"
                >
                  {`{{${tag}}}`}
                </button>
              ))}
            </div>

            {/* Editor Mode Tabs & Visual Toolbar */}
            <div className="border border-[#262A2E] rounded-lg overflow-hidden">
              <div className="bg-[#171A1D] border-b border-[#262A2E] px-3 py-2 flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => formatDoc("bold")}
                    className="p-1.5 rounded hover:bg-[#1D2125] text-zinc-400 hover:text-white"
                    title="Bold"
                  >
                    <Bold className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => formatDoc("italic")}
                    className="p-1.5 rounded hover:bg-[#1D2125] text-zinc-400 hover:text-white"
                    title="Italic"
                  >
                    <Italic className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => formatDoc("insertUnorderedList")}
                    className="p-1.5 rounded hover:bg-[#1D2125] text-zinc-400 hover:text-white"
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
                    className="p-1.5 rounded hover:bg-[#1D2125] text-zinc-400 hover:text-white"
                    title="Insert Link"
                  >
                    <LinkIcon className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="flex items-center bg-[#111315] p-0.5 rounded-md text-xs font-mono border border-[#262A2E]">
                  <button
                    type="button"
                    onClick={() => setEditorMode("visual")}
                    className={`px-2.5 py-1 rounded text-[11px] transition-colors ${
                      editorMode === "visual"
                        ? "bg-[#171A1D] text-white font-medium"
                        : "text-zinc-500 hover:text-zinc-300"
                    }`}
                  >
                    Visual
                  </button>
                  <button
                    type="button"
                    onClick={() => setEditorMode("html")}
                    className={`px-2.5 py-1 rounded text-[11px] transition-colors ${
                      editorMode === "html"
                        ? "bg-[#171A1D] text-white font-medium"
                        : "text-zinc-500 hover:text-zinc-300"
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
                  className="min-h-[360px] p-4 text-sm text-zinc-100 bg-[#0D0F11] focus:outline-none overflow-y-auto font-sans leading-relaxed"
                  style={{ minHeight: "360px" }}
                />
              ) : (
                <textarea
                  rows={16}
                  value={htmlContent}
                  onChange={(e) => setHtmlContent(e.target.value)}
                  className="w-full p-4 font-mono text-xs text-zinc-200 bg-[#0D0F11] focus:outline-none resize-y"
                  style={{ minHeight: "360px" }}
                />
              )}
            </div>

            {/* Plain Text Fallback Section */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-[11px] font-mono text-zinc-400">
                  Plain-Text Fallback
                </label>
                <button
                  type="button"
                  onClick={() => setTextContent(htmlToPlainText(htmlContent))}
                  className="text-[11px] font-mono text-zinc-400 hover:text-white transition-colors"
                >
                  Generate from HTML
                </button>
              </div>
              <textarea
                rows={3}
                value={textContent}
                onChange={(e) => setTextContent(e.target.value)}
                placeholder="Plain text version for text-only clients..."
                className="w-full p-2.5 text-xs font-mono bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none"
              />
            </div>

            {/* Email Attachments (PDF & Documents) Section */}
            <div className="pt-3 border-t border-[#1C2024] space-y-2.5">
              <div className="flex items-center justify-between">
                <label className="text-xs font-mono uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
                  <Paperclip className="w-3.5 h-3.5 text-zinc-400" />
                  <span>Attachments</span>
                  {attachments.length > 0 && (
                    <span className="text-[10px] bg-[#171A1D] text-zinc-300 border border-[#262A2E] px-1.5 py-0.5 rounded font-mono">
                      {attachments.length}/5
                    </span>
                  )}
                </label>
                <label className="cursor-pointer inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono text-zinc-300 bg-[#171A1D] border border-[#262A2E] rounded-lg hover:border-zinc-500 hover:text-white transition-colors">
                  <Upload className="w-3.5 h-3.5 text-zinc-400" />
                  <span>Attach PDF / File</span>
                  <input
                    type="file"
                    multiple
                    accept=".pdf,application/pdf,image/*,.doc,.docx,.txt,.csv"
                    onChange={handleAttachmentChange}
                    className="hidden"
                  />
                </label>
              </div>

              {attachmentError && (
                <div className="flex items-center gap-1.5 text-red-400 text-xs bg-red-950/40 p-2.5 rounded-lg border border-red-500/30 font-mono">
                  <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
                  <span>{attachmentError}</span>
                </div>
              )}

              {attachments.length === 0 ? (
                <div className="text-center py-4 px-3 border border-dashed border-[#262A2E] rounded-lg bg-[#171A1D]/20">
                  <p className="text-xs text-zinc-500 font-mono">
                    No files attached. Up to 4 MB per file (max 5 attachments).
                  </p>
                </div>
              ) : (
                <div className="space-y-1.5">
                  {attachments.map((file, fileIdx) => {
                    const isPdf = file.filename.toLowerCase().endsWith(".pdf") || file.contentType.includes("pdf");
                    const sizeFormatted = file.size < 1024 * 1024
                      ? `${(file.size / 1024).toFixed(1)} KB`
                      : `${(file.size / (1024 * 1024)).toFixed(2)} MB`;
                    return (
                      <div
                        key={file.id || fileIdx}
                        className="flex items-center justify-between p-2.5 rounded-lg border border-[#262A2E] bg-[#171A1D] hover:border-zinc-600 transition-colors"
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          <div className="p-1.5 rounded bg-[#111315] border border-[#262A2E] text-zinc-400">
                            <FileText className="w-4 h-4" />
                          </div>
                          <div className="truncate">
                            <span className="text-xs font-medium text-white block truncate">
                              {file.filename}
                            </span>
                            <span className="text-[10px] text-zinc-500 font-mono">
                              {isPdf ? "PDF Document" : file.contentType} · {sizeFormatted}
                            </span>
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => removeAttachment(file.id || fileIdx)}
                          className="p-1 text-zinc-500 hover:text-red-400 rounded transition-colors"
                          title="Remove attachment"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* MODAL 1: Choose Template Modal */}
      <AnimatePresence>
        {templateModalOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4"
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.96, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.97, y: 6 }}
              transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
              className="bg-[#111315] rounded-xl border border-[#262A2E] max-w-2xl w-full p-6 space-y-4 max-h-[85vh] overflow-y-auto"
            >
              <div className="flex items-center justify-between border-b border-[#262A2E] pb-3">
                <h3 className="text-sm font-medium text-white">Choose an Email Template</h3>
                <button onClick={() => setTemplateModalOpen(false)} className="p-1 text-zinc-400 hover:text-white">
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {availableTemplates.length === 0 ? (
                  <div className="col-span-2 py-8 text-center text-xs font-mono text-zinc-500">
                    No saved templates found. Create custom templates in the Templates section.
                  </div>
                ) : (
                  availableTemplates.map((tmpl) => (
                    <div
                      key={tmpl.id}
                      onClick={() => {
                        setSubject(tmpl.subject);
                        setHtmlContent(tmpl.htmlContent);
                        setTextContent(tmpl.textContent || htmlToPlainText(tmpl.htmlContent));
                        if (tmpl.attachments && tmpl.attachments.length > 0) {
                          setAttachments(tmpl.attachments);
                        }
                        setTemplateModalOpen(false);
                      }}
                      className="p-4 border border-[#262A2E] rounded-xl hover:border-zinc-500 cursor-pointer transition-all bg-[#171A1D] hover:-translate-y-0.5"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-medium text-white">{tmpl.name}</span>
                        <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-[#111315] border border-[#262A2E] text-zinc-400">
                          {tmpl.category}
                        </span>
                      </div>
                      <p className="text-xs text-zinc-400 line-clamp-2 mt-1">{tmpl.description}</p>
                    </div>
                  ))
                )}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* MODAL 2: Interactive Live Preview Modal */}
      <AnimatePresence>
        {previewOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4"
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.96, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.97, y: 6 }}
              transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
              className="bg-[#111315] rounded-xl border border-[#262A2E] max-w-3xl w-full p-6 space-y-4 max-h-[90vh] flex flex-col"
            >
              <div className="flex items-center justify-between border-b border-[#262A2E] pb-3">
                <div>
                  <h3 className="text-sm font-medium text-white">Email Preview & Personalization Check</h3>
                  <p className="text-xs text-zinc-500 font-mono mt-0.5">
                    Simulating recipient {previewRecipientIndex + 1} of {Math.max(1, activeSelectedRecipients.length)}
                  </p>
                </div>
                <button onClick={() => setPreviewOpen(false)} className="p-1 text-zinc-400 hover:text-white">
                  <X className="w-5 h-5" />
                </button>
              </div>

            {/* Recipient switcher */}
            {activeSelectedRecipients.length > 1 && (
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="text-zinc-500">Preview as:</span>
                <select
                  value={previewRecipientIndex}
                  onChange={(e) => setPreviewRecipientIndex(Number(e.target.value))}
                  className="px-2 py-1 bg-[#171A1D] border border-[#262A2E] text-white rounded text-xs focus:outline-none"
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
            <div className="p-3 bg-[#171A1D] border border-[#262A2E] rounded-lg text-xs space-y-1 font-mono">
              <div>
                <span className="text-zinc-500">From: </span>
                <span className="text-zinc-200 font-mono">
                  "{fromName}" &lt;{fromEmail}&gt;
                </span>
              </div>
              <div>
                <span className="text-zinc-500">To: </span>
                <span className="text-zinc-200 font-mono">{previewTarget.email}</span>
              </div>
              <div>
                <span className="text-zinc-500">Subject: </span>
                <span className="text-white font-sans font-medium">{previewSubject}</span>
              </div>
              {attachments.length > 0 && (
                <div>
                  <span className="text-zinc-500">Attachments: </span>
                  <span className="text-zinc-300">
                    {attachments.map((a) => a.filename).join(", ")} ({attachments.length} file{attachments.length > 1 ? "s" : ""})
                  </span>
                </div>
              )}
            </div>

            {/* Rendered HTML Body */}
            <div className="flex-1 overflow-y-auto border border-[#262A2E] rounded-lg p-6 bg-white text-slate-900 shadow-inner">
              <div
                dangerouslySetInnerHTML={{ __html: previewHtml }}
                className="font-sans leading-relaxed text-sm"
              />
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>

      {/* MODAL 3: Confirm & Schedule Dispatch Modal */}
      <AnimatePresence>
        {confirmSendOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4"
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.96, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.97, y: 6 }}
              transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
              className="bg-[#111315] rounded-xl border border-[#262A2E] max-w-md w-full p-6 space-y-4"
            >
              <h3 className="text-base font-medium text-white">Confirm Campaign Dispatch</h3>

              <div className="p-4 bg-[#171A1D] border border-[#262A2E] rounded-xl text-xs space-y-2 font-mono">
                <div className="flex justify-between">
                  <span className="text-zinc-400">Recipients:</span>
                  <span className="text-white font-medium">{activeSelectedRecipients.length} addresses</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-400">Sender Identity:</span>
                  <span className="text-zinc-300">{fromEmail}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-400">Delivery Transport:</span>
                  <span className="text-emerald-400">
                    {profile?.settings?.smtp?.host ? `SMTP (${profile.settings.smtp.host})` : "Direct SMTP"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-400">Tracking:</span>
                  <span className="text-zinc-300">
                    {trackOpens ? "Opens " : ""}{trackClicks ? "& Clicks" : ""}{!trackOpens && !trackClicks ? "Disabled" : ""}
                  </span>
                </div>
                {attachments.length > 0 && (
                  <div className="flex justify-between">
                    <span className="text-zinc-400">Attachments:</span>
                    <span className="text-white">{attachments.length} file(s)</span>
                  </div>
                )}
              </div>

              {/* Schedule Option */}
              <div className="pt-2 border-t border-[#262A2E]">
                <label className="flex items-center gap-2 text-xs font-mono text-zinc-300 cursor-pointer mb-2">
                  <input
                    type="checkbox"
                    checked={scheduleMode}
                    onChange={(e) => setScheduleMode(e.target.checked)}
                    className="rounded bg-[#111315] border-[#262A2E] text-white focus:ring-0"
                  />
                  <span>Schedule for future date & time</span>
                </label>

                {scheduleMode && (
                  <input
                    type="datetime-local"
                    value={scheduleDateTime}
                    onChange={(e) => setScheduleDateTime(e.target.value)}
                    className="w-full px-3 py-1.5 text-xs bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:outline-none font-mono"
                  />
                )}
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  onClick={() => setConfirmSendOpen(false)}
                  className="px-4 py-2 text-xs font-mono text-zinc-400 hover:text-white rounded-lg"
                >
                  Cancel
                </button>
                <button
                  onClick={handleExecuteSend}
                  className="px-4 py-2 text-xs font-medium text-black bg-white hover:bg-zinc-200 rounded-lg transition-colors"
                >
                  {scheduleMode ? "Schedule Campaign" : "Dispatch Campaign"}
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* MODAL 4: Real-time Dispatch Progress Modal */}
      <AnimatePresence>
        {isProcessing && sendProgress && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4"
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.96, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.97, y: 6 }}
              transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
              className="bg-[#111315] rounded-xl border border-[#262A2E] max-w-md w-full p-6 text-center space-y-4"
            >
              <RefreshCw className="w-8 h-8 text-white animate-spin mx-auto" />
              <h3 className="text-base font-medium text-white">Dispatching Bulk Campaign</h3>
              <p className="text-xs text-zinc-400 font-mono">{sendProgress.statusText}</p>

              {/* Progress Bar */}
              <div className="w-full bg-[#171A1D] border border-[#262A2E] rounded-full h-2 overflow-hidden">
                <div
                  className="bg-white h-full transition-all duration-300 rounded-full"
                  style={{
                    width: `${
                      sendProgress.total > 0
                        ? ((sendProgress.sent + sendProgress.failed) / sendProgress.total) * 100
                        : 0
                    }%`,
                  }}
                />
              </div>

              <div className="flex justify-between text-xs text-zinc-500 font-mono pt-1">
                <span>{sendProgress.sent} dispatched</span>
                <span>{sendProgress.failed} failed</span>
                <span>{sendProgress.total} total</span>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
