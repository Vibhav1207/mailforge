"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useAuth } from "@/context/auth-context";
import { getCampaigns } from "@/lib/store/db-service";
import { Campaign } from "@/types";
import { formatDate, formatNumber } from "@/lib/utils";
import {
  History,
  Search,
  Filter,
  BarChart2,
  TrendingUp,
  CheckCircle2,
  AlertCircle,
  Clock,
  ArrowUpRight,
  ShieldCheck,
  Send,
  Calendar,
  Eye,
  MousePointerClick,
} from "lucide-react";

export default function SendingHistoryPage() {
  const { user, profile } = useAuth();
  const userId = user?.uid || profile?.uid || "";

  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedStatus, setSelectedStatus] = useState<string>("all");

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const data = await getCampaigns(userId);
        setCampaigns(data);
      } catch (err) {
        console.error("Load history error:", err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [userId]);

  // Aggregate stats
  const totalSent = campaigns.reduce((acc, c) => acc + (c.stats?.sent || 0), 0);
  const totalDelivered = campaigns.reduce((acc, c) => acc + (c.stats?.delivered || 0), 0);
  const totalOpened = campaigns.reduce((acc, c) => acc + (c.stats?.opened || 0), 0);
  const totalClicked = campaigns.reduce((acc, c) => acc + (c.stats?.clicked || 0), 0);
  const totalBounced = campaigns.reduce((acc, c) => acc + (c.stats?.bounced || 0), 0);
  const totalFailed = campaigns.reduce((acc, c) => acc + (c.stats?.failed || 0), 0);
  const totalUnsubscribed = campaigns.reduce((acc, c) => acc + (c.stats?.unsubscribed || 0), 0);

  const deliveryRate = totalSent > 0 ? ((totalDelivered / totalSent) * 100).toFixed(1) : "0.0";
  const openRate = totalDelivered > 0 ? ((totalOpened / totalDelivered) * 100).toFixed(1) : "0.0";
  const clickRate = totalDelivered > 0 ? ((totalClicked / totalDelivered) * 100).toFixed(1) : "0.0";
  const bounceRate = totalSent > 0 ? ((totalBounced / totalSent) * 100).toFixed(1) : "0.0";

  const filteredCampaigns = campaigns.filter((c) => {
    const matchesSearch =
      c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.subject.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = selectedStatus === "all" || c.status === selectedStatus;
    return matchesSearch && matchesStatus;
  });

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900">
          Sending History & Analytics
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          Audit past email campaigns, track open rates, link clicks, and delivery performance.
        </p>
      </div>

      {/* Aggregate Telemetry Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-6 gap-3">
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
          <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            Total Sent
          </span>
          <p className="text-2xl font-bold text-slate-900 mt-1">{formatNumber(totalSent)}</p>
          <p className="text-[11px] text-slate-400 mt-0.5">Dispatched emails</p>
        </div>

        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
          <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            Delivered
          </span>
          <p className="text-2xl font-bold text-emerald-600 mt-1">{formatNumber(totalDelivered)}</p>
          <p className="text-[11px] text-emerald-600 mt-0.5">{deliveryRate}% delivery rate</p>
        </div>

        <div className="bg-white p-4 rounded-xl border border-blue-200 shadow-sm bg-blue-50/20">
          <span className="text-[11px] font-semibold text-blue-700 uppercase tracking-wider flex items-center gap-1">
            <Eye className="w-3 h-3 text-blue-600" />
            Opened
          </span>
          <p className="text-2xl font-bold text-blue-700 mt-1">{formatNumber(totalOpened)}</p>
          <p className="text-[11px] text-blue-600 font-medium mt-0.5">{openRate}% open rate</p>
        </div>

        <div className="bg-white p-4 rounded-xl border border-indigo-200 shadow-sm bg-indigo-50/20">
          <span className="text-[11px] font-semibold text-indigo-700 uppercase tracking-wider flex items-center gap-1">
            <MousePointerClick className="w-3 h-3 text-indigo-600" />
            Clicked
          </span>
          <p className="text-2xl font-bold text-indigo-700 mt-1">{formatNumber(totalClicked)}</p>
          <p className="text-[11px] text-indigo-600 font-medium mt-0.5">{clickRate}% CTR</p>
        </div>

        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
          <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            Bounced
          </span>
          <p className="text-2xl font-bold text-amber-600 mt-1">{formatNumber(totalBounced)}</p>
          <p className="text-[11px] text-amber-600 mt-0.5">{bounceRate}% bounce rate</p>
        </div>

        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
          <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            Failed
          </span>
          <p className="text-2xl font-bold text-red-600 mt-1">{formatNumber(totalFailed)}</p>
          <p className="text-[11px] text-slate-400 mt-0.5">{formatNumber(totalUnsubscribed)} opt-outs</p>
        </div>
      </div>

      {/* Visual Volume and Performance Breakdown */}
      <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
          <div className="flex items-center gap-2">
            <BarChart2 className="w-5 h-5 text-blue-600" />
            <h2 className="text-sm font-semibold text-slate-900">Campaign Delivery & Engagement Ratio</h2>
          </div>
          <span className="text-xs text-slate-500">Live Telemetry</span>
        </div>

        {totalSent > 0 ? (
          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-xs text-slate-700 mb-1">
                <span>Engagement Proportion</span>
                <span className="font-semibold text-blue-600">{openRate}% Opened · {clickRate}% Clicked</span>
              </div>
              <div className="w-full h-3 bg-slate-100 rounded-full overflow-hidden flex">
                <div
                  className="bg-blue-500 h-full"
                  style={{ width: `${Math.min(100, (totalOpened / (totalSent || 1)) * 100)}%` }}
                  title="Opened"
                />
                <div
                  className="bg-indigo-500 h-full"
                  style={{ width: `${Math.min(100, (totalClicked / (totalSent || 1)) * 100)}%` }}
                  title="Clicked"
                />
                <div
                  className="bg-amber-400 h-full"
                  style={{ width: `${Math.min(100, (totalBounced / (totalSent || 1)) * 100)}%` }}
                  title="Bounced"
                />
                <div
                  className="bg-red-500 h-full"
                  style={{ width: `${Math.min(100, (totalFailed / (totalSent || 1)) * 100)}%` }}
                  title="Failed"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-6 text-xs text-slate-600 pt-2">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-blue-500" />
                <span>Opened ({totalOpened})</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-indigo-500" />
                <span>Clicked ({totalClicked})</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-emerald-500" />
                <span>Delivered ({totalDelivered})</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-amber-400" />
                <span>Bounced ({totalBounced})</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-red-500" />
                <span>Failed ({totalFailed})</span>
              </div>
            </div>
          </div>
        ) : (
          <div className="p-8 text-center text-xs text-slate-500">
            Send your first campaign to generate real telemetry visualization.
          </div>
        )}
      </div>

      {/* History Table & Filters */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
        <div className="p-4 border-b border-slate-200 flex flex-col sm:flex-row gap-3 items-center justify-between">
          <div className="relative w-full sm:w-72">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search history..."
              className="w-full pl-9 pr-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 focus:outline-none"
            />
          </div>

          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 bg-white"
          >
            <option value="all">All Statuses</option>
            <option value="completed">Completed</option>
            <option value="completed_with_errors">With Errors</option>
            <option value="failed">Failed</option>
          </select>
        </div>

        {filteredCampaigns.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-500">No history records found.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-semibold uppercase tracking-wider text-[11px]">
                  <th className="py-3 px-4">Campaign</th>
                  <th className="py-3 px-4">Dispatched Date</th>
                  <th className="py-3 px-4">Total</th>
                  <th className="py-3 px-4">Delivered</th>
                  <th className="py-3 px-4 text-blue-700">Opened</th>
                  <th className="py-3 px-4 text-indigo-700">Clicked</th>
                  <th className="py-3 px-4">Bounced</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredCampaigns.map((c) => {
                  const campSent = c.stats?.sent || c.recipientCount || 1;
                  const campOpened = c.stats?.opened || 0;
                  const campClicked = c.stats?.clicked || 0;
                  const campOpenRate = ((campOpened / campSent) * 100).toFixed(0);
                  const campClickRate = ((campClicked / campSent) * 100).toFixed(0);

                  return (
                    <tr key={c.id} className="hover:bg-slate-50/60 transition-colors">
                      <td className="py-3 px-4">
                        <Link
                          href={`/dashboard/campaigns/${c.id}`}
                          className="font-bold text-slate-900 hover:text-blue-600 block"
                        >
                          {c.name}
                        </Link>
                        <span className="text-[11px] text-slate-500 truncate block max-w-xs">
                          {c.subject}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-500">
                        {formatDate(c.completedAt || c.createdAt)}
                      </td>
                      <td className="py-3 px-4 font-semibold text-slate-800">
                        {c.recipientCount}
                      </td>
                      <td className="py-3 px-4 text-emerald-600 font-semibold">
                        {c.stats?.delivered || 0}
                      </td>
                      <td className="py-3 px-4 text-blue-700 font-semibold">
                        <div className="flex items-center gap-1.5">
                          <Eye className="w-3.5 h-3.5 text-blue-500" />
                          <span>{campOpened}</span>
                          <span className="text-[10px] text-blue-500 font-normal">({campOpenRate}%)</span>
                        </div>
                      </td>
                      <td className="py-3 px-4 text-indigo-700 font-semibold">
                        <div className="flex items-center gap-1.5">
                          <MousePointerClick className="w-3.5 h-3.5 text-indigo-500" />
                          <span>{campClicked}</span>
                          <span className="text-[10px] text-indigo-500 font-normal">({campClickRate}%)</span>
                        </div>
                      </td>
                      <td className="py-3 px-4 text-amber-600 font-semibold">
                        {c.stats?.bounced || 0}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <Link
                          href={`/dashboard/campaigns/${c.id}`}
                          className="text-xs font-semibold text-blue-600 hover:underline inline-flex items-center justify-end gap-1"
                        >
                          <span>Full Report</span>
                          <ArrowUpRight className="w-3.5 h-3.5" />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
