"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/context/auth-context";
import { getCampaigns, getContacts } from "@/lib/store/db-service";
import { Campaign, Contact } from "@/types";
import { formatDate, formatNumber } from "@/lib/utils";
import {
  Send,
  Users,
  CheckCircle2,
  AlertCircle,
  Megaphone,
  ArrowUpRight,
  TrendingUp,
  Clock,
  ShieldCheck,
  Plus,
  RefreshCw,
  ExternalLink,
  Eye,
  MousePointerClick,
} from "lucide-react";

export default function DashboardOverviewPage() {
  const { user, profile } = useAuth();
  const userId = user?.uid || profile?.uid || "";

  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [loading, setLoading] = useState(true);

  const loadDashboardData = async () => {
    setLoading(true);
    try {
      const [cmpList, cntList] = await Promise.all([
        getCampaigns(userId),
        getContacts(userId),
      ]);
      setCampaigns(cmpList);
      setContacts(cntList);
    } catch (e) {
      console.error("Dashboard data load error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, [userId]);

  // Aggregate high-accuracy statistics
  const totalEmailsSent = campaigns.reduce((acc, c) => acc + (c.stats?.sent || 0), 0);
  const totalDelivered = campaigns.reduce((acc, c) => acc + (c.stats?.delivered || 0), 0);
  const totalOpened = campaigns.reduce((acc, c) => acc + (c.stats?.opened || 0), 0);
  const totalClicked = campaigns.reduce((acc, c) => acc + (c.stats?.clicked || 0), 0);
  const totalFailed = campaigns.reduce((acc, c) => acc + (c.stats?.failed || 0), 0);
  const totalBounced = campaigns.reduce((acc, c) => acc + (c.stats?.bounced || 0), 0);
  const totalContacts = contacts.length;
  const activeContacts = contacts.filter((c) => c.status === "active").length;
  const suppressedContacts = contacts.filter((c) => c.status !== "active").length;
  const totalCampaigns = campaigns.length;

  const deliveryRate = totalEmailsSent > 0 ? ((totalDelivered / totalEmailsSent) * 100).toFixed(1) : "0.0";
  const openRate = totalEmailsSent > 0 ? ((totalOpened / totalEmailsSent) * 100).toFixed(1) : "0.0";
  const clickRate = totalEmailsSent > 0 ? ((totalClicked / totalEmailsSent) * 100).toFixed(1) : "0.0";

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Dashboard</h1>
          <p className="text-sm text-slate-500 mt-1">
            Real-time delivery telemetry, opens & clicks engagement, and recipient metrics.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadDashboardData}
            disabled={loading}
            className="p-2 text-slate-600 hover:text-slate-900 bg-white border border-slate-200 rounded-lg shadow-sm hover:bg-slate-50 transition-colors"
            title="Refresh statistics"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
          <Link
            href="/dashboard/compose"
            className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-semibold shadow-sm transition-colors"
          >
            <Plus className="w-4 h-4" />
            <span>New Campaign</span>
          </Link>
        </div>
      </div>

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        {/* Total Sent */}
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider">Total Sent</span>
            <div className="w-7 h-7 rounded-lg bg-blue-50 text-blue-600 flex items-center justify-center">
              <Send className="w-3.5 h-3.5" />
            </div>
          </div>
          <p className="text-2xl font-bold text-slate-900">{formatNumber(totalEmailsSent)}</p>
          <div className="mt-2 text-xs text-slate-500">
            <span className="text-emerald-600 font-medium">{totalCampaigns}</span> campaigns
          </div>
        </div>

        {/* Confirmed Delivered */}
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider">Delivered</span>
            <div className="w-7 h-7 rounded-lg bg-emerald-50 text-emerald-600 flex items-center justify-center">
              <CheckCircle2 className="w-3.5 h-3.5" />
            </div>
          </div>
          <p className="text-2xl font-bold text-slate-900">{formatNumber(totalDelivered)}</p>
          <div className="mt-2 text-xs text-slate-500">
            <span className="text-emerald-600 font-semibold">{deliveryRate}%</span> rate
          </div>
        </div>

        {/* Opened Emails */}
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider">Opened</span>
            <div className="w-7 h-7 rounded-lg bg-indigo-50 text-indigo-600 flex items-center justify-center">
              <Eye className="w-3.5 h-3.5" />
            </div>
          </div>
          <p className="text-2xl font-bold text-indigo-600">{formatNumber(totalOpened)}</p>
          <div className="mt-2 text-xs text-slate-500">
            <span className="text-indigo-600 font-semibold">{openRate}%</span> open rate
          </div>
        </div>

        {/* Clicked Links */}
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider">Clicked</span>
            <div className="w-7 h-7 rounded-lg bg-purple-50 text-purple-600 flex items-center justify-center">
              <TrendingUp className="w-3.5 h-3.5" />
            </div>
          </div>
          <p className="text-2xl font-bold text-purple-600">{formatNumber(totalClicked)}</p>
          <div className="mt-2 text-xs text-slate-500">
            <span className="text-purple-600 font-semibold">{clickRate}%</span> CTR
          </div>
        </div>

        {/* Failed / Bounced */}
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider">Failed / Bounce</span>
            <div className="w-7 h-7 rounded-lg bg-red-50 text-red-600 flex items-center justify-center">
              <AlertCircle className="w-3.5 h-3.5" />
            </div>
          </div>
          <p className="text-2xl font-bold text-slate-900">{formatNumber(totalFailed + totalBounced)}</p>
          <div className="mt-2 text-xs text-slate-500">
            <span>{totalBounced} bnc · {totalFailed} fail</span>
          </div>
        </div>

        {/* Total Contacts */}
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider">Contacts</span>
            <div className="w-7 h-7 rounded-lg bg-violet-50 text-violet-600 flex items-center justify-center">
              <Users className="w-3.5 h-3.5" />
            </div>
          </div>
          <p className="text-2xl font-bold text-slate-900">{formatNumber(totalContacts)}</p>
          <div className="mt-2 text-xs text-slate-500">
            <span>{activeContacts} active audience</span>
          </div>
        </div>
      </div>

      {/* Main Split: Recent Campaigns & Activity Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Recent Campaigns Table */}
        <div className="lg:col-span-2 bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
          <div className="p-5 border-b border-slate-200 flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-slate-900">Recent Campaigns</h2>
              <p className="text-xs text-slate-500 mt-0.5">Most recent email campaigns and their status</p>
            </div>
            <Link
              href="/dashboard/campaigns"
              className="text-xs font-medium text-blue-600 hover:text-blue-700 flex items-center gap-1"
            >
              <span>View all</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {campaigns.length === 0 ? (
            <div className="p-12 text-center">
              <Megaphone className="w-10 h-10 text-slate-300 mx-auto mb-3" />
              <h3 className="text-sm font-semibold text-slate-900">No campaigns created yet</h3>
              <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
                Create and personalize your first campaign to begin dispatching to your audience.
              </p>
              <Link
                href="/dashboard/compose"
                className="mt-4 inline-flex items-center gap-2 px-3 py-1.5 bg-blue-600 text-white rounded-lg text-xs font-medium"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Create Campaign</span>
              </Link>
            </div>
          ) : (
            <div className="divide-y divide-slate-100">
              {campaigns.slice(0, 5).map((cmp) => {
                const statusStyles: Record<string, string> = {
                  completed: "bg-emerald-50 text-emerald-700 border-emerald-200",
                  completed_with_errors: "bg-amber-50 text-amber-700 border-amber-200",
                  sending: "bg-blue-50 text-blue-700 border-blue-200 animate-pulse",
                  queued: "bg-indigo-50 text-indigo-700 border-indigo-200",
                  draft: "bg-slate-100 text-slate-700 border-slate-200",
                  failed: "bg-red-50 text-red-700 border-red-200",
                  scheduled: "bg-purple-50 text-purple-700 border-purple-200",
                };

                return (
                  <div key={cmp.id} className="p-4 sm:p-5 hover:bg-slate-50/60 transition-colors flex items-center justify-between gap-4">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <Link
                          href={`/dashboard/campaigns/${cmp.id}`}
                          className="font-semibold text-sm text-slate-900 hover:text-blue-600 truncate"
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
                      <p className="text-xs text-slate-500 truncate">{cmp.subject}</p>
                      <div className="flex items-center gap-3 text-[11px] text-slate-400 mt-2">
                        <span>{formatDate(cmp.createdAt)}</span>
                        <span>•</span>
                        <span>{cmp.recipientCount} recipients</span>
                        {cmp.stats?.sent > 0 && (
                          <>
                            <span>•</span>
                            <span className="text-emerald-600 font-medium">
                              {cmp.stats.delivered || cmp.stats.sent} sent
                            </span>
                          </>
                        )}
                      </div>
                    </div>

                    <Link
                      href={`/dashboard/campaigns/${cmp.id}`}
                      className="px-3 py-1.5 text-xs font-medium text-slate-700 hover:text-slate-900 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 shadow-sm shrink-0"
                    >
                      View Report
                    </Link>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Quick Actions & Delivery Infrastructure Status */}
        <div className="space-y-6">
          {/* Infrastructure Health Card */}
          <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
            <h3 className="text-sm font-semibold text-slate-900 mb-3 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-600" />
              Delivery Infrastructure
            </h3>
            <div className="space-y-3 text-xs">
              <div className="flex items-center justify-between py-1.5 border-b border-slate-100">
                <span className="text-slate-500">Delivery Engine</span>
                <span className="font-semibold text-slate-800">Gmail App Password / SMTP</span>
              </div>
              <div className="flex items-center justify-between py-1.5 border-b border-slate-100">
                <span className="text-slate-500">Sender Authentication</span>
                <span className="font-semibold text-emerald-600">SSL 465 / TLS Active</span>
              </div>
              <div className="flex items-center justify-between py-1.5 border-b border-slate-100">
                <span className="text-slate-500">Suppression Engine</span>
                <span className="font-semibold text-blue-600">Enforced Pre-Send</span>
              </div>
              <div className="flex items-center justify-between py-1.5">
                <span className="text-slate-500">Template Image Storage</span>
                <span className="font-semibold text-emerald-700">MongoDB Folders</span>
              </div>
            </div>
          </div>

          {/* Quick Actions Card */}
          <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
            <h3 className="text-sm font-semibold text-slate-900 mb-3">Quick Navigation</h3>
            <div className="space-y-2">
              <Link
                href="/dashboard/contacts"
                className="w-full flex items-center justify-between p-2.5 rounded-lg border border-slate-200 hover:bg-slate-50 text-xs font-medium text-slate-700 transition-colors"
              >
                <div className="flex items-center gap-2.5">
                  <Users className="w-4 h-4 text-slate-500" />
                  <span>Import & Manage Contacts</span>
                </div>
                <ArrowUpRight className="w-3.5 h-3.5 text-slate-400" />
              </Link>

              <Link
                href="/dashboard/templates"
                className="w-full flex items-center justify-between p-2.5 rounded-lg border border-slate-200 hover:bg-slate-50 text-xs font-medium text-slate-700 transition-colors"
              >
                <div className="flex items-center gap-2.5">
                  <Megaphone className="w-4 h-4 text-slate-500" />
                  <span>Browse Email Templates</span>
                </div>
                <ArrowUpRight className="w-3.5 h-3.5 text-slate-400" />
              </Link>

              <Link
                href="/dashboard/settings"
                className="w-full flex items-center justify-between p-2.5 rounded-lg border border-slate-200 hover:bg-slate-50 text-xs font-medium text-slate-700 transition-colors"
              >
                <div className="flex items-center gap-2.5">
                  <ShieldCheck className="w-4 h-4 text-slate-500" />
                  <span>Sender Identities & Settings</span>
                </div>
                <ArrowUpRight className="w-3.5 h-3.5 text-slate-400" />
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
