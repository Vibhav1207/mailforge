"use client";

import React, { useState, useEffect } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/context/auth-context";
import { getCampaignById, saveCampaign, getCampaignRecipients } from "@/lib/store/db-service";
import { apiFetch } from "@/lib/api-client";
import { Campaign, CampaignRecipient } from "@/types";
import { formatDate, formatNumber } from "@/lib/utils";
import {
  ArrowLeft,
  RefreshCw,
  Send,
  AlertCircle,
  CheckCircle2,
  Clock,
  RotateCcw,
  ChevronRight,
  Eye,
  Activity,
  Layers,
  FileText,
} from "lucide-react";

export default function CampaignDetailPage() {
  const params = useParams();
  const router = useRouter();
  const campaignId = params.id as string;
  const { user, profile } = useAuth();
  const userId = user?.uid || profile?.uid || "";

  const [campaign, setCampaign] = useState<Campaign | null>(null);
  const [recipients, setRecipients] = useState<CampaignRecipient[]>([]);
  const [loading, setLoading] = useState(true);
  const [retrying, setRetrying] = useState(false);
  const [resuming, setResuming] = useState(false);
  const [activeTab, setActiveTab] = useState<"results" | "content">("results");

  const loadCampaignData = async () => {
    setLoading(true);
    try {
      const cmp = await getCampaignById(userId, campaignId);
      setCampaign(cmp);

      if (cmp) {
        const campaignRecipients = await getCampaignRecipients(userId, campaignId);
        setRecipients(campaignRecipients);
      }
    } catch (e) {
      console.error("Load campaign error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCampaignData();
  }, [campaignId, userId]);

  // Automated Continuous Sending Engine:
  // Auto-resumes processing batches until 100% of recipients are delivered
  useEffect(() => {
    if (!campaign || !userId) return;
    if (!["queued", "sending"].includes(campaign.status)) return;

    let isCancelled = false;
    let isExecuting = false;

    const runAutoStep = async () => {
      if (isExecuting || isCancelled) return;
      isExecuting = true;
      try {
        const res = await apiFetch(`/api/campaigns/${campaignId}/resume`, { method: "POST" });
        if (res.ok) {
          const data = await res.json();
          if (!isCancelled && data.campaign) {
            setCampaign(data.campaign);
            const updatedRecipients = await getCampaignRecipients(userId, campaignId);
            if (!isCancelled) setRecipients(updatedRecipients);
          }
        } else {
          // Fall back to reading latest campaign status
          const updatedCampaign = await getCampaignById(userId, campaignId);
          if (!isCancelled && updatedCampaign) setCampaign(updatedCampaign);
        }
      } catch (error) {
        console.warn("Auto-resume step error:", error);
      } finally {
        isExecuting = false;
      }
    };

    runAutoStep();
    const interval = window.setInterval(runAutoStep, 2_000);
    return () => {
      isCancelled = true;
      window.clearInterval(interval);
    };
  }, [campaign?.status, campaignId, userId]);

  // Retry eligible transient failures without resending succeeded messages
  const handleRetryFailed = async () => {
    if (!campaign) return;
    const failedOnes = recipients.filter((r) => r.status === "failed");
    if (failedOnes.length === 0) {
      alert("No failed recipients eligible for retry.");
      return;
    }

    setRetrying(true);
    try {
      const res = await apiFetch(`/api/campaigns/${campaign.id}/retry`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          campaign,
          failedRecipients: failedOnes.map((f) => ({
            recipientId: f.id,
            email: f.email,
            firstName: f.firstName,
            lastName: f.lastName,
            company: f.company,
          })),
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Retry dispatch failed");

      setRecipients((prev) =>
        prev.map((r) => {
          if (r.status === "failed") {
            return {
              ...r,
              status: "sent",
              attempts: r.attempts + 1,
              error: undefined,
              sentAt: new Date().toISOString(),
            };
          }
          return r;
        })
      );

      const updatedCmp: Campaign = {
        ...campaign,
        stats: {
          ...campaign.stats,
          sent: campaign.stats.sent + failedOnes.length,
          failed: Math.max(0, campaign.stats.failed - failedOnes.length),
        },
        status: "completed",
        updatedAt: new Date().toISOString(),
      };
      setCampaign(updatedCmp);
      await saveCampaign(updatedCmp);

      alert(`Successfully retried ${failedOnes.length} failed messages.`);
    } catch (err: any) {
      alert(err.message || "Retry failed");
    } finally {
      setRetrying(false);
    }
  };

  const handleResume = async () => {
    if (!campaign) return;
    setResuming(true);
    try {
      const res = await apiFetch(`/api/campaigns/${campaign.id}/resume`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Resume failed");
      await loadCampaignData();
    } catch (err: any) {
      alert(err.message || "Resume failed");
    } finally {
      setResuming(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24 text-xs font-mono text-zinc-500">
        <RefreshCw className="w-4 h-4 animate-spin mr-2" />
        LOADING CAMPAIGN TELEMETRY...
      </div>
    );
  }

  if (!campaign) {
    return (
      <div className="p-12 text-center space-y-4 bg-[#111315] border border-[#262A2E] rounded-xl max-w-md mx-auto my-12">
        <AlertCircle className="w-8 h-8 text-zinc-500 mx-auto" />
        <h2 className="text-base font-medium text-white">Campaign Not Found</h2>
        <p className="text-xs text-zinc-400">The requested campaign ID does not exist or has been removed.</p>
        <Link
          href="/dashboard/campaigns"
          className="inline-flex items-center gap-2 text-xs text-white bg-[#171A1D] border border-[#262A2E] hover:border-zinc-500 px-3.5 py-1.5 rounded-lg transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Campaigns</span>
        </Link>
      </div>
    );
  }

  const failedRecipientsCount = recipients.filter((r) => r.status === "failed").length;

  return (
    <div className="space-y-6">
      {/* Top Breadcrumb */}
      <div className="flex items-center gap-2 text-xs text-zinc-400 font-mono">
        <Link href="/dashboard/campaigns" className="hover:text-white transition-colors">
          Campaigns
        </Link>
        <ChevronRight className="w-3.5 h-3.5 text-zinc-600" />
        <span className="text-zinc-200 truncate max-w-sm font-sans font-medium">{campaign.name}</span>
      </div>

      {/* Campaign Details Header Card */}
      <div className="bg-[#111315] p-6 rounded-xl border border-[#262A2E] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5 mb-1.5">
            <h1 className="text-xl font-medium tracking-tight text-white">{campaign.name}</h1>
            {["queued", "sending"].includes(campaign.status) ? (
              <span className="inline-flex items-center gap-1.5 text-[11px] font-mono px-2 py-0.5 rounded border border-emerald-500/30 bg-emerald-950/40 text-emerald-400">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                AUTO-SENDING ACTIVE
              </span>
            ) : (
              <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded border border-[#262A2E] bg-[#171A1D] text-zinc-300">
                {campaign.status.replace("_", " ")}
              </span>
            )}
          </div>
          <p className="text-xs text-zinc-400 font-mono">Subject: <span className="text-zinc-200">{campaign.subject}</span></p>
          <p className="text-xs text-zinc-500 font-mono mt-1">
            Sender: "{campaign.fromName}" &lt;{campaign.fromEmail}&gt; · Created {formatDate(campaign.createdAt)}
          </p>
        </div>

        <div className="flex items-center gap-2">
          {["queued", "sending"].includes(campaign.status) && (
            <button
              onClick={handleResume}
              disabled={resuming}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-black bg-white hover:bg-zinc-200 rounded-lg transition-colors disabled:opacity-50"
            >
              <Send className={`w-3.5 h-3.5 ${resuming ? "animate-spin" : ""}`} />
              <span>{resuming ? "Resuming..." : "Force Next Batch"}</span>
            </button>
          )}

          {failedRecipientsCount > 0 && (
            <button
              onClick={handleRetryFailed}
              disabled={retrying}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-amber-300 bg-amber-950/50 hover:bg-amber-900/60 border border-amber-800/60 rounded-lg transition-colors disabled:opacity-50"
            >
              <RotateCcw className={`w-3.5 h-3.5 ${retrying ? "animate-spin" : ""}`} />
              <span>Retry {failedRecipientsCount} Failed</span>
            </button>
          )}

          <button
            onClick={loadCampaignData}
            className="p-2 text-zinc-400 hover:text-white bg-[#171A1D] border border-[#262A2E] hover:border-zinc-600 rounded-lg transition-colors"
            title="Refresh Report"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* KPI Stats Breakdown */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="bg-[#111315] p-4 rounded-xl border border-[#262A2E]">
          <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider block">
            Total Recipients
          </span>
          <p className="text-2xl font-mono font-medium text-white mt-1">
            {formatNumber(campaign.recipientCount || recipients.length)}
          </p>
        </div>

        <div className="bg-[#111315] p-4 rounded-xl border border-[#262A2E]">
          <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider block">
            Accepted / Sent
          </span>
          <p className="text-2xl font-mono font-medium text-white mt-1">
            {formatNumber(campaign.stats?.sent || 0)}
          </p>
        </div>

        <div className="bg-[#111315] p-4 rounded-xl border border-[#262A2E]">
          <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider block">
            Confirmed Delivered
          </span>
          <p className="text-2xl font-mono font-medium text-emerald-400 mt-1">
            {formatNumber(campaign.stats?.delivered || campaign.stats?.sent || 0)}
          </p>
        </div>

        <div className="bg-[#111315] p-4 rounded-xl border border-[#262A2E]">
          <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider block">
            Opened Emails
          </span>
          <p className="text-2xl font-mono font-medium text-white mt-1">
            {formatNumber(campaign.stats?.opened || 0)}
          </p>
          <span className="text-[10px] font-mono text-zinc-400">
            {campaign.stats?.sent ? ((Number(campaign.stats?.opened || 0) / campaign.stats.sent) * 100).toFixed(1) : "0"}% rate
          </span>
        </div>

        <div className="bg-[#111315] p-4 rounded-xl border border-[#262A2E]">
          <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider block">
            Link Clicks
          </span>
          <p className="text-2xl font-mono font-medium text-white mt-1">
            {formatNumber(campaign.stats?.clicked || 0)}
          </p>
          <span className="text-[10px] font-mono text-zinc-400">
            {campaign.stats?.sent ? ((Number(campaign.stats?.clicked || 0) / campaign.stats.sent) * 100).toFixed(1) : "0"}% CTR
          </span>
        </div>

        <div className="bg-[#111315] p-4 rounded-xl border border-[#262A2E]">
          <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider block">
            Failed / Bounced
          </span>
          <p className="text-2xl font-mono font-medium text-red-400 mt-1">
            {formatNumber((campaign.stats?.failed || 0) + (campaign.stats?.bounced || 0))}
          </p>
        </div>
      </div>

      {/* Tabs: Recipient-Level Results vs HTML Email Content */}
      <div className="bg-[#111315] rounded-xl border border-[#262A2E] overflow-hidden">
        <div className="border-b border-[#262A2E] px-6 py-3 flex items-center justify-between">
          <div className="flex gap-6 text-xs font-medium">
            <button
              onClick={() => setActiveTab("results")}
              className={`pb-2 border-b-2 transition-colors flex items-center gap-1.5 ${
                activeTab === "results"
                  ? "border-white text-white"
                  : "border-transparent text-zinc-400 hover:text-zinc-200"
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Recipient Audit Log ({recipients.length})</span>
            </button>
            <button
              onClick={() => setActiveTab("content")}
              className={`pb-2 border-b-2 transition-colors flex items-center gap-1.5 ${
                activeTab === "content"
                  ? "border-white text-white"
                  : "border-transparent text-zinc-400 hover:text-zinc-200"
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Rendered Email Content</span>
            </button>
          </div>
        </div>

        {activeTab === "results" ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-[#171A1D]/60 border-b border-[#262A2E] text-zinc-400 font-mono text-[11px] uppercase tracking-wider">
                  <th className="py-3 px-4 font-medium">Recipient</th>
                  <th className="py-3 px-4 font-medium">Delivery Status</th>
                  <th className="py-3 px-4 font-medium">Engagement</th>
                  <th className="py-3 px-4 font-medium">Provider Message ID</th>
                  <th className="py-3 px-4 font-medium">Timestamp</th>
                  <th className="py-3 px-4 font-medium">Diagnostics</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1C2024]">
                {recipients.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-zinc-500 font-mono text-xs">
                      No recipients registered in this campaign
                    </td>
                  </tr>
                ) : (
                  recipients.map((r) => {
                    const statusColors: Record<string, string> = {
                      delivered: "border-emerald-500/30 bg-emerald-950/40 text-emerald-400",
                      sent: "border-blue-500/30 bg-blue-950/40 text-blue-400",
                      failed: "border-red-500/30 bg-red-950/40 text-red-400",
                      bounced: "border-amber-500/30 bg-amber-950/40 text-amber-400",
                      pending: "border-zinc-700 bg-zinc-800 text-zinc-400",
                    };

                    return (
                      <tr key={r.id} className="hover:bg-[#171A1D]/40 transition-colors">
                        <td className="py-3 px-4">
                          <p className="font-medium text-white">
                            {[r.firstName, r.lastName].filter(Boolean).join(" ") || "—"}
                          </p>
                          <p className="font-mono text-zinc-400 text-[11px]">{r.email}</p>
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`inline-block px-2 py-0.5 rounded text-[10px] font-mono uppercase border ${
                              statusColors[r.status] || "border-zinc-700 bg-zinc-800 text-zinc-400"
                            }`}
                          >
                            {r.status}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex flex-wrap items-center gap-1.5">
                            {r.openCount && r.openCount > 0 ? (
                              <span className="px-1.5 py-0.5 rounded border border-[#262A2E] bg-[#171A1D] text-white font-mono text-[10px]">
                                Opened ({r.openCount}x)
                              </span>
                            ) : (
                              <span className="text-zinc-600 font-mono text-[11px]">Unopened</span>
                            )}
                            {r.clickCount && r.clickCount > 0 ? (
                              <span className="px-1.5 py-0.5 rounded border border-purple-500/30 bg-purple-950/40 text-purple-300 font-mono text-[10px]">
                                Clicked ({r.clickCount}x)
                              </span>
                            ) : null}
                          </div>
                        </td>
                        <td className="py-3 px-4 font-mono text-[11px] text-zinc-400">
                          {r.providerMessageId ? (
                            <span className="truncate max-w-[200px] block" title={r.providerMessageId}>
                              {r.providerMessageId}
                            </span>
                          ) : (
                            "—"
                          )}
                        </td>
                        <td className="py-3 px-4 text-zinc-400 font-mono text-[11px]">
                          {formatDate(r.deliveredAt || r.sentAt)}
                        </td>
                        <td className="py-3 px-4 text-xs">
                          {r.error ? (
                            <span className="text-red-400 text-[11px] flex items-center gap-1 font-mono">
                              <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                              <span className="truncate max-w-xs" title={r.error}>{r.error}</span>
                            </span>
                          ) : (
                            <span className="text-emerald-400 text-[11px] flex items-center gap-1 font-mono">
                              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                              <span>Accepted by MTA</span>
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-6 bg-[#08090A]">
            <div className="bg-white text-slate-900 p-8 rounded-xl border border-zinc-700 max-w-2xl mx-auto shadow-2xl">
              <div
                dangerouslySetInnerHTML={{ __html: campaign.htmlContent }}
                className="font-sans leading-relaxed text-sm"
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
