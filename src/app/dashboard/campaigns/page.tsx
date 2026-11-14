"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/context/auth-context";
import {
  getCampaigns,
  deleteCampaign,
  saveCampaign,
} from "@/lib/store/db-service";
import { Campaign } from "@/types";
import { formatDate, formatNumber } from "@/lib/utils";
import { motion } from "motion/react";
import {
  Megaphone,
  Plus,
  Search,
  Copy,
  Trash2,
  Eye,
  Calendar,
  XCircle,
  RefreshCw,
} from "lucide-react";

export default function CampaignsPage() {
  const router = useRouter();
  const { user, profile } = useAuth();
  const userId = user?.uid || profile?.uid || "";

  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const loadData = async (forceRefresh = false) => {
    if (!userId) return;
    setLoading(true);
    try {
      const data = await getCampaigns(userId, forceRefresh);
      setCampaigns(data);
    } catch (err) {
      console.error("Failed to load campaigns:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!userId) return;
    loadData();
  }, [userId]);

  // Duplicate a campaign
  const handleDuplicate = async (cmp: Campaign) => {
    const newId = `cmp_${Date.now()}`;
    const duplicated: Campaign = {
      ...cmp,
      id: newId,
      name: `${cmp.name} (Copy)`,
      status: "draft",
      stats: { total: cmp.recipientCount, sent: 0, delivered: 0, bounced: 0, failed: 0, unsubscribed: 0 },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      completedAt: null,
      scheduledFor: null,
    };

    await saveCampaign(duplicated);
    await loadData(true);
    router.push(`/dashboard/campaigns/${newId}`);
  };

  // Delete a campaign
  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to delete this campaign?")) return;
    await deleteCampaign(userId, id);
    await loadData(true);
  };

  // Cancel scheduled campaign
  const handleCancelSchedule = async (cmp: Campaign) => {
    if (!confirm("Cancel this scheduled campaign?")) return;
    const updated: Campaign = {
      ...cmp,
      status: "cancelled",
      updatedAt: new Date().toISOString(),
    };
    await saveCampaign(updated);
    await loadData(true);
  };

  const filteredCampaigns = campaigns.filter((c) => {
    const matchesSearch =
      c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.subject.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === "all" || c.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <div className="space-y-6 font-sans">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-6 border-b border-[#1C2024]">
        <div>
          <h1 className="text-2xl font-semibold tracking-[-0.02em] text-[#F5F5F5]">Campaigns</h1>
          <p className="text-xs text-[#A1A1AA] mt-1 font-mono">
            Manage drafts, scheduled broadcasts, active delivery jobs, and past campaign telemetry
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <motion.button
            whileHover={{ y: -1 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => loadData(true)}
            disabled={loading}
            className="p-2 text-[#A1A1AA] hover:text-white bg-[#111315] hover:bg-[#171A1D] border border-[#262A2E] hover:border-zinc-500 rounded-md transition-colors"
            title="Refresh"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          </motion.button>
          <motion.div whileHover={{ y: -1 }} whileTap={{ scale: 0.97 }}>
            <Link
              href="/dashboard/compose"
              className="inline-flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold text-[#08090A] bg-white hover:bg-[#E5E7EB] rounded-md shadow-sm transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Campaign</span>
            </Link>
          </motion.div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-3 rounded-lg bg-[#111315] border border-[#262A2E] flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="relative w-full sm:w-80">
          <Search className="w-3.5 h-3.5 text-[#71717A] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search campaigns..."
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-[#0D0F11] text-[#F5F5F5] border border-[#1C2024] rounded-md focus:border-[#45494E] focus:outline-none placeholder:text-[#71717A] font-mono"
          />
        </div>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="w-full sm:w-auto px-3 py-1.5 text-xs bg-[#0D0F11] text-[#A1A1AA] border border-[#1C2024] rounded-md focus:border-[#45494E] focus:outline-none font-mono"
        >
          <option value="all">All Statuses</option>
          <option value="draft">Drafts</option>
          <option value="scheduled">Scheduled</option>
          <option value="sending">Sending</option>
          <option value="completed">Completed</option>
          <option value="completed_with_errors">Completed With Errors</option>
          <option value="failed">Failed</option>
          <option value="cancelled">Cancelled</option>
        </select>
      </div>

      {/* Campaigns List Card */}
      <div className="rounded-xl bg-[#111315] border border-[#262A2E] overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-xs font-mono text-[#71717A]">Loading campaigns...</div>
        ) : filteredCampaigns.length === 0 ? (
          <div className="p-12 text-center">
            <Megaphone className="w-8 h-8 text-[#45494E] mx-auto mb-3" />
            <h3 className="text-sm font-medium text-[#F5F5F5]">No campaigns found</h3>
            <p className="text-xs text-[#71717A] mt-1 max-w-sm mx-auto font-mono">
              Start by composing and dispatching your first bulk campaign.
            </p>
            <Link
              href="/dashboard/compose"
              className="mt-4 inline-flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold text-[#08090A] bg-white hover:bg-[#E5E7EB] rounded-md"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Compose Campaign</span>
            </Link>
          </div>
        ) : (
          <div className="divide-y divide-[#1C2024]">
            {filteredCampaigns.map((cmp) => {
              const isCompleted = cmp.status === "completed";
              const isSending = ["sending", "queued"].includes(cmp.status);
              const isFailed = cmp.status === "failed";
              const isScheduled = cmp.status === "scheduled";
              const isCancelled = cmp.status === "cancelled";

              return (
                <div
                  key={cmp.id}
                  className="p-4 sm:p-5 hover:bg-[#171A1D]/50 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2.5 mb-1">
                      <Link
                        href={`/dashboard/campaigns/${cmp.id}`}
                        className="font-medium text-sm text-[#F5F5F5] hover:text-white truncate"
                      >
                        {cmp.name}
                      </Link>
                      <span
                        className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${
                          isCompleted
                            ? "bg-[#102719] text-[#22C55E] border-[#22C55E]/30"
                            : isSending
                            ? "bg-[#111315] text-[#60A5FA] border-[#60A5FA]/30"
                            : isFailed
                            ? "bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/30"
                            : isScheduled
                            ? "bg-[#F59E0B]/10 text-[#F59E0B] border-[#F59E0B]/30"
                            : isCancelled
                            ? "bg-[#171A1D] text-[#71717A] border-[#262A2E] line-through"
                            : "bg-[#171A1D] text-[#A1A1AA] border-[#262A2E]"
                        }`}
                      >
                        {cmp.status.replace("_", " ")}
                      </span>
                    </div>

                    <p className="text-xs text-[#A1A1AA] truncate font-mono">
                      Subject: {cmp.subject}
                    </p>

                    <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-[#71717A] mt-1.5">
                      <span>{formatDate(cmp.createdAt)}</span>
                      <span>·</span>
                      <span>From: {cmp.fromName} &lt;{cmp.fromEmail}&gt;</span>
                      {cmp.scheduledFor && (
                        <>
                          <span>·</span>
                          <span className="flex items-center gap-1 text-[#F59E0B]">
                            <Calendar className="w-3 h-3" />
                            Scheduled: {formatDate(cmp.scheduledFor)}
                          </span>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Telemetry Numbers & Actions */}
                  <div className="flex items-center gap-6 sm:justify-end shrink-0 pt-2 sm:pt-0 border-t sm:border-t-0 border-[#1C2024]">
                    <div className="text-right">
                      <span className="text-sm font-mono font-semibold text-[#F5F5F5] block">
                        {formatNumber(cmp.recipientCount || cmp.stats?.total || 0)}
                      </span>
                      <span className="text-[10px] font-mono text-[#71717A] block">
                        {cmp.stats?.sent ? `${cmp.stats.sent} sent` : "recipients"}
                      </span>
                    </div>

                    {cmp.stats?.sent ? (
                      <div className="text-right">
                        <span className="text-sm font-mono font-semibold text-[#22C55E] block">
                          {((cmp.stats.opened || 0) / (cmp.stats.sent || 1) * 100).toFixed(1)}%
                        </span>
                        <span className="text-[10px] font-mono text-[#71717A] block">open rate</span>
                      </div>
                    ) : null}

                    <div className="flex items-center gap-1.5">
                      <Link
                        href={`/dashboard/campaigns/${cmp.id}`}
                        className="p-1.5 text-[#A1A1AA] hover:text-white hover:bg-[#1D2125] rounded transition-colors"
                        title="View Report"
                      >
                        <Eye className="w-4 h-4" />
                      </Link>

                      <button
                        onClick={() => handleDuplicate(cmp)}
                        className="p-1.5 text-[#A1A1AA] hover:text-white hover:bg-[#1D2125] rounded transition-colors"
                        title="Duplicate Campaign"
                      >
                        <Copy className="w-4 h-4" />
                      </button>

                      {cmp.status === "scheduled" && (
                        <button
                          onClick={() => handleCancelSchedule(cmp)}
                          className="p-1.5 text-[#F59E0B] hover:bg-[#1D2125] rounded transition-colors"
                          title="Cancel Scheduled Send"
                        >
                          <XCircle className="w-4 h-4" />
                        </button>
                      )}

                      <button
                        onClick={() => handleDelete(cmp.id)}
                        className="p-1.5 text-[#71717A] hover:text-[#EF4444] hover:bg-[#1D2125] rounded transition-colors"
                        title="Delete Campaign"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
