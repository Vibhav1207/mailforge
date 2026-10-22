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
  Mail,
  ShieldCheck,
  Copy,
  RotateCcw,
  ExternalLink,
  ChevronRight,
  Eye,
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

      // Update local state
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

  if (loading) {
    return <div className="p-12 text-center text-xs text-slate-500">Loading campaign report...</div>;
  }

  if (!campaign) {
    return (
      <div className="p-12 text-center space-y-4">
        <h2 className="text-base font-bold text-slate-900">Campaign Not Found</h2>
        <Link
          href="/dashboard/campaigns"
          className="inline-flex items-center gap-2 text-xs text-blue-600 hover:underline"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Campaigns</span>
        </Link>
      </div>
    );
  }

  const failedRecipientsCount = recipients.filter((r) => r.status === "failed").length;

  return (
    <div className="space-y-6">
      {/* Top Navigation & Breadcrumb */}
      <div className="flex items-center gap-2 text-xs text-slate-500">
        <Link href="/dashboard/campaigns" className="hover:text-slate-900">
          Campaigns
        </Link>
        <ChevronRight className="w-3.5 h-3.5" />
        <span className="font-semibold text-slate-900 truncate max-w-sm">{campaign.name}</span>
      </div>

      {/* Campaign Details Header Card */}
      <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-xl font-bold tracking-tight text-slate-900">{campaign.name}</h1>
            <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded border bg-blue-50 text-blue-700 border-blue-200">
              {campaign.status.replace("_", " ")}
            </span>
          </div>
          <p className="text-xs text-slate-600 font-mono mt-1">Subject: {campaign.subject}</p>
          <p className="text-xs text-slate-400 mt-0.5">
            Sender: "{campaign.fromName}" &lt;{campaign.fromEmail}&gt; · Created {formatDate(campaign.createdAt)}
          </p>
        </div>

        <div className="flex items-center gap-2">
          {failedRecipientsCount > 0 && (
            <button
              onClick={handleRetryFailed}
              disabled={retrying}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-amber-800 bg-amber-50 hover:bg-amber-100 border border-amber-200 rounded-lg shadow-sm transition-all disabled:opacity-50"
            >
              <RotateCcw className={`w-3.5 h-3.5 ${retrying ? "animate-spin" : ""}`} />
              <span>Retry {failedRecipientsCount} Failed</span>
            </button>
          )}

          <button
            onClick={loadCampaignData}
            className="p-2 text-slate-600 hover:text-slate-900 bg-white border border-slate-200 rounded-lg shadow-sm hover:bg-slate-50"
            title="Refresh Report"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* KPI Stats Breakdown */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
          <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            Total Recipients
          </span>
          <p className="text-2xl font-bold text-slate-900 mt-1">
            {formatNumber(campaign.recipientCount || recipients.length)}
          </p>
        </div>

        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
          <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            Accepted / Sent
          </span>
          <p className="text-2xl font-bold text-blue-600 mt-1">
            {formatNumber(campaign.stats?.sent || 0)}
          </p>
        </div>

        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
          <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            Confirmed Delivered
          </span>
          <p className="text-2xl font-bold text-emerald-600 mt-1">
            {formatNumber(campaign.stats?.delivered || campaign.stats?.sent || 0)}
          </p>
        </div>

        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
          <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            Opened Emails
          </span>
          <p className="text-2xl font-bold text-indigo-600 mt-1">
            {formatNumber(campaign.stats?.opened || 0)}
          </p>
          <span className="text-[11px] text-indigo-600 font-medium">
            {campaign.stats?.sent ? ((Number(campaign.stats?.opened || 0) / campaign.stats.sent) * 100).toFixed(1) : "0"}% Open Rate
          </span>
        </div>

        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
          <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            Link Clicks
          </span>
          <p className="text-2xl font-bold text-purple-600 mt-1">
            {formatNumber(campaign.stats?.clicked || 0)}
          </p>
          <span className="text-[11px] text-purple-600 font-medium">
            {campaign.stats?.sent ? ((Number(campaign.stats?.clicked || 0) / campaign.stats.sent) * 100).toFixed(1) : "0"}% CTR
          </span>
        </div>

        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
          <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            Failed / Bounced
          </span>
          <p className="text-2xl font-bold text-red-600 mt-1">
            {formatNumber((campaign.stats?.failed || 0) + (campaign.stats?.bounced || 0))}
          </p>
        </div>
      </div>

      {/* Tabs: Recipient-Level Results vs HTML Email Content */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
        <div className="border-b border-slate-200 px-6 py-3 flex items-center justify-between">
          <div className="flex gap-4 text-xs font-semibold">
            <button
              onClick={() => setActiveTab("results")}
              className={`pb-2 border-b-2 transition-colors ${
                activeTab === "results"
                  ? "border-blue-600 text-blue-600"
                  : "border-transparent text-slate-500 hover:text-slate-900"
              }`}
            >
              Recipient Audit Log ({recipients.length})
            </button>
            <button
              onClick={() => setActiveTab("content")}
              className={`pb-2 border-b-2 transition-colors ${
                activeTab === "content"
                  ? "border-blue-600 text-blue-600"
                  : "border-transparent text-slate-500 hover:text-slate-900"
              }`}
            >
              Rendered Email Content
            </button>
          </div>
        </div>

        {activeTab === "results" ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-semibold uppercase tracking-wider text-[11px]">
                  <th className="py-3 px-4">Recipient</th>
                  <th className="py-3 px-4">Delivery Status</th>
                  <th className="py-3 px-4">Engagement (Opens/Clicks)</th>
                  <th className="py-3 px-4">Provider Message ID</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Diagnostics</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {recipients.map((r) => {
                  const statusColors: Record<string, string> = {
                    delivered: "bg-emerald-50 text-emerald-700 border-emerald-200",
                    sent: "bg-blue-50 text-blue-700 border-blue-200",
                    failed: "bg-red-50 text-red-700 border-red-200",
                    bounced: "bg-amber-50 text-amber-700 border-amber-200",
                  };

                  return (
                    <tr key={r.id} className="hover:bg-slate-50/60 transition-colors">
                      <td className="py-3 px-4">
                        <p className="font-semibold text-slate-900">
                          {[r.firstName, r.lastName].filter(Boolean).join(" ") || "—"}
                        </p>
                        <p className="font-mono text-slate-500 text-[11px]">{r.email}</p>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                            statusColors[r.status] || "bg-slate-100 text-slate-700"
                          }`}
                        >
                          {r.status}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap items-center gap-1.5">
                          {r.openCount && r.openCount > 0 ? (
                            <span className="px-1.5 py-0.5 rounded bg-indigo-50 border border-indigo-200 text-indigo-700 font-semibold text-[10px]">
                              Opened ({r.openCount}x)
                            </span>
                          ) : (
                            <span className="text-slate-400 text-[11px]">Unopened</span>
                          )}
                          {r.clickCount && r.clickCount > 0 ? (
                            <span className="px-1.5 py-0.5 rounded bg-purple-50 border border-purple-200 text-purple-700 font-semibold text-[10px]">
                              Clicked ({r.clickCount}x)
                            </span>
                          ) : null}
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-600">
                        {r.providerMessageId || "—"}
                      </td>
                      <td className="py-3 px-4 text-slate-500">
                        {formatDate(r.deliveredAt || r.sentAt)}
                      </td>
                      <td className="py-3 px-4 text-slate-600">
                        {r.error ? (
                          <span className="text-red-600 text-[11px] flex items-center gap-1">
                            <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                            <span>{r.error}</span>
                          </span>
                        ) : (
                          <span className="text-emerald-600 text-[11px] flex items-center gap-1">
                            <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                            <span>Provider accepted</span>
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-6 bg-slate-50">
            <div className="bg-white p-6 rounded-xl border border-slate-200 max-w-2xl mx-auto shadow-sm">
              <div
                dangerouslySetInnerHTML={{ __html: campaign.htmlContent }}
                className="font-sans"
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
