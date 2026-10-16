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
import { Campaign, CampaignStatus } from "@/types";
import { formatDate, formatNumber } from "@/lib/utils";
import {
  Megaphone,
  Plus,
  Search,
  Filter,
  Copy,
  Trash2,
  Edit,
  ArrowUpRight,
  Clock,
  CheckCircle2,
  AlertCircle,
  XCircle,
  Send,
  Calendar,
} from "lucide-react";

export default function CampaignsPage() {
  const router = useRouter();
  const { user, profile } = useAuth();
  const userId = user?.uid || profile?.uid || "";

  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await getCampaigns(userId);
      setCampaigns(data);
    } catch (err) {
      console.error("Failed to load campaigns:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
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
    await loadData();
    router.push(`/dashboard/campaigns/${newId}`);
  };

  // Delete a campaign
  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to delete this campaign?")) return;
    await deleteCampaign(userId, id);
    await loadData();
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
    await loadData();
  };

  const filteredCampaigns = campaigns.filter((c) => {
    const matchesSearch =
      c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.subject.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === "all" || c.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Campaigns</h1>
          <p className="text-sm text-slate-500 mt-1">
            Manage drafts, scheduled broadcasts, active delivery jobs, and past campaign telemetry.
          </p>
        </div>

        <Link
          href="/dashboard/compose"
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg shadow-sm transition-all"
        >
          <Plus className="w-4 h-4" />
          <span>New Campaign</span>
        </Link>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search campaigns by name or subject..."
            className="w-full pl-9 pr-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 focus:outline-none"
          />
        </div>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-2.5 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 bg-white text-slate-700"
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
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-xs text-slate-500">Loading campaigns...</div>
        ) : filteredCampaigns.length === 0 ? (
          <div className="p-12 text-center">
            <Megaphone className="w-10 h-10 text-slate-300 mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-slate-900">No campaigns found</h3>
            <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
              Start by creating and dispatching your first bulk email broadcast.
            </p>
            <Link
              href="/dashboard/compose"
              className="mt-4 inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-white bg-blue-600 rounded-lg shadow-sm"
            >
              <Plus className="w-4 h-4" />
              <span>Compose Campaign</span>
            </Link>
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {filteredCampaigns.map((cmp) => {
              const statusStyles: Record<string, string> = {
                completed: "bg-emerald-50 text-emerald-700 border-emerald-200",
                completed_with_errors: "bg-amber-50 text-amber-700 border-amber-200",
                sending: "bg-blue-50 text-blue-700 border-blue-200 animate-pulse",
                queued: "bg-indigo-50 text-indigo-700 border-indigo-200",
                draft: "bg-slate-100 text-slate-700 border-slate-200",
                failed: "bg-red-50 text-red-700 border-red-200",
                scheduled: "bg-purple-50 text-purple-700 border-purple-200",
                cancelled: "bg-slate-100 text-slate-500 border-slate-200 line-through",
              };

              return (
                <div
                  key={cmp.id}
                  className="p-5 hover:bg-slate-50/60 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-1.5">
                      <Link
                        href={`/dashboard/campaigns/${cmp.id}`}
                        className="font-bold text-sm text-slate-900 hover:text-blue-600 truncate"
                      >
                        {cmp.name}
                      </Link>
                      <span
                        className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                          statusStyles[cmp.status] || "bg-slate-100 text-slate-700"
                        }`}
                      >
                        {cmp.status.replace("_", " ")}
                      </span>
                    </div>

                    <p className="text-xs text-slate-600 truncate">{cmp.subject}</p>

                    <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-400 mt-2">
                      <span>Created {formatDate(cmp.createdAt)}</span>
                      {cmp.scheduledFor && (
                        <>
                          <span>•</span>
                          <span className="text-purple-600 font-medium flex items-center gap-1">
                            <Calendar className="w-3 h-3" />
                            Scheduled for {formatDate(cmp.scheduledFor)}
                          </span>
                        </>
                      )}
                      {cmp.completedAt && (
                        <>
                          <span>•</span>
                          <span>Completed {formatDate(cmp.completedAt)}</span>
                        </>
                      )}
                      <span>•</span>
                      <span>{cmp.recipientCount} recipients</span>
                      {cmp.stats?.sent > 0 && (
                        <>
                          <span>•</span>
                          <span className="text-emerald-600 font-semibold">
                            {cmp.stats.delivered || cmp.stats.sent} sent
                          </span>
                        </>
                      )}
                      {cmp.stats?.failed > 0 && (
                        <>
                          <span>•</span>
                          <span className="text-red-600 font-semibold">{cmp.stats.failed} failed</span>
                        </>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 self-end sm:self-center shrink-0">
                    {cmp.status === "scheduled" && (
                      <button
                        onClick={() => handleCancelSchedule(cmp)}
                        className="px-2.5 py-1.5 text-xs font-medium text-amber-700 hover:bg-amber-50 rounded-lg border border-amber-200"
                      >
                        Cancel Schedule
                      </button>
                    )}

                    <Link
                      href={`/dashboard/campaigns/${cmp.id}`}
                      className="px-3 py-1.5 text-xs font-semibold text-slate-700 hover:text-slate-900 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 shadow-sm"
                    >
                      View Details
                    </Link>

                    <button
                      onClick={() => handleDuplicate(cmp)}
                      className="p-1.5 text-slate-400 hover:text-slate-700 rounded-lg hover:bg-slate-100"
                      title="Duplicate Campaign"
                    >
                      <Copy className="w-4 h-4" />
                    </button>

                    <button
                      onClick={() => handleDelete(cmp.id)}
                      className="p-1.5 text-slate-400 hover:text-red-600 rounded-lg hover:bg-red-50"
                      title="Delete Campaign"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
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
