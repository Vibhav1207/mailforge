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
  BarChart2,
  CheckCircle2,
  AlertCircle,
  Clock,
  ArrowUpRight,
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
    if (!userId) return;
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
        <h1 className="text-xl font-medium tracking-tight text-white">
          Sending History & Analytics
        </h1>
        <p className="text-xs text-zinc-400 font-mono mt-1">
          Historical campaign telemetry, deliverability ratios, and recipient engagement.
        </p>
      </div>

      {/* Aggregate Telemetry Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-6 gap-3">
        <div className="bg-[#111315] p-4 rounded-xl border border-[#262A2E]">
          <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider block">
            Total Sent
          </span>
          <p className="text-2xl font-mono font-medium text-white mt-1">{formatNumber(totalSent)}</p>
          <p className="text-[10px] font-mono text-zinc-500 mt-0.5">Dispatches</p>
        </div>

        <div className="bg-[#111315] p-4 rounded-xl border border-[#262A2E]">
          <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider block">
            Delivered
          </span>
          <p className="text-2xl font-mono font-medium text-emerald-400 mt-1">{formatNumber(totalDelivered)}</p>
          <p className="text-[10px] font-mono text-emerald-400/80 mt-0.5">{deliveryRate}% rate</p>
        </div>

        <div className="bg-[#111315] p-4 rounded-xl border border-[#262A2E]">
          <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider flex items-center gap-1">
            <Eye className="w-3 h-3 text-zinc-400" />
            Opened
          </span>
          <p className="text-2xl font-mono font-medium text-white mt-1">{formatNumber(totalOpened)}</p>
          <p className="text-[10px] font-mono text-zinc-400 mt-0.5">{openRate}% rate</p>
        </div>

        <div className="bg-[#111315] p-4 rounded-xl border border-[#262A2E]">
          <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider flex items-center gap-1">
            <MousePointerClick className="w-3 h-3 text-zinc-400" />
            Clicked
          </span>
          <p className="text-2xl font-mono font-medium text-white mt-1">{formatNumber(totalClicked)}</p>
          <p className="text-[10px] font-mono text-zinc-400 mt-0.5">{clickRate}% CTR</p>
        </div>

        <div className="bg-[#111315] p-4 rounded-xl border border-[#262A2E]">
          <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider block">
            Bounced
          </span>
          <p className="text-2xl font-mono font-medium text-amber-400 mt-1">{formatNumber(totalBounced)}</p>
          <p className="text-[10px] font-mono text-amber-400/80 mt-0.5">{bounceRate}% rate</p>
        </div>

        <div className="bg-[#111315] p-4 rounded-xl border border-[#262A2E]">
          <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider block">
            Failed
          </span>
          <p className="text-2xl font-mono font-medium text-red-400 mt-1">{formatNumber(totalFailed)}</p>
          <p className="text-[10px] font-mono text-zinc-500 mt-0.5">{formatNumber(totalUnsubscribed)} opt-outs</p>
        </div>
      </div>

      {/* Visual Volume and Performance Breakdown */}
      <div className="bg-[#111315] p-5 rounded-xl border border-[#262A2E] space-y-4">
        <div className="flex items-center justify-between border-b border-[#262A2E] pb-3">
          <div className="flex items-center gap-2">
            <BarChart2 className="w-4 h-4 text-zinc-400" />
            <h2 className="text-xs font-mono uppercase tracking-wider text-zinc-400">Campaign Delivery & Engagement Ratio</h2>
          </div>
          <span className="text-[11px] font-mono text-zinc-500">Live Telemetry</span>
        </div>

        {totalSent > 0 ? (
          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-xs font-mono text-zinc-400 mb-2">
                <span>Engagement Proportion</span>
                <span className="text-white">{openRate}% Opened · {clickRate}% Clicked</span>
              </div>
              <div className="w-full h-2.5 bg-[#171A1D] border border-[#262A2E] rounded-full overflow-hidden flex">
                <div
                  className="bg-zinc-200 h-full"
                  style={{ width: `${Math.min(100, (totalOpened / (totalSent || 1)) * 100)}%` }}
                  title="Opened"
                />
                <div
                  className="bg-zinc-400 h-full"
                  style={{ width: `${Math.min(100, (totalClicked / (totalSent || 1)) * 100)}%` }}
                  title="Clicked"
                />
                <div
                  className="bg-amber-500 h-full"
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

            <div className="flex flex-wrap items-center gap-6 text-xs font-mono text-zinc-400 pt-1">
              <div className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full bg-zinc-200" />
                <span>Opened ({totalOpened})</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full bg-zinc-400" />
                <span>Clicked ({totalClicked})</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
                <span>Delivered ({totalDelivered})</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full bg-amber-400" />
                <span>Bounced ({totalBounced})</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full bg-red-400" />
                <span>Failed ({totalFailed})</span>
              </div>
            </div>
          </div>
        ) : (
          <div className="p-8 text-center text-xs font-mono text-zinc-500">
            Send your first campaign to generate real telemetry visualization.
          </div>
        )}
      </div>

      {/* History Table & Filters */}
      <div className="bg-[#111315] rounded-xl border border-[#262A2E] overflow-hidden">
        <div className="p-3 border-b border-[#262A2E] flex flex-col sm:flex-row gap-3 items-center justify-between">
          <div className="relative w-full sm:w-72">
            <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search history..."
              className="w-full pl-9 pr-3 py-1.5 text-xs bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none font-mono"
            />
          </div>

          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="px-2.5 py-1.5 text-xs font-mono bg-[#171A1D] border border-[#262A2E] text-zinc-300 rounded-lg focus:outline-none"
          >
            <option value="all">All Statuses</option>
            <option value="completed">Completed</option>
            <option value="completed_with_errors">With Errors</option>
            <option value="failed">Failed</option>
          </select>
        </div>

        {filteredCampaigns.length === 0 ? (
          <div className="p-12 text-center text-xs font-mono text-zinc-500">No history records found.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-[#171A1D]/60 border-b border-[#262A2E] text-zinc-400 font-mono text-[11px] uppercase tracking-wider">
                  <th className="py-3 px-4 font-medium">Campaign</th>
                  <th className="py-3 px-4 font-medium">Dispatched</th>
                  <th className="py-3 px-4 font-medium">Total</th>
                  <th className="py-3 px-4 font-medium">Delivered</th>
                  <th className="py-3 px-4 font-medium">Opened</th>
                  <th className="py-3 px-4 font-medium">Clicked</th>
                  <th className="py-3 px-4 font-medium">Bounced</th>
                  <th className="py-3 px-4 text-right font-medium">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1C2024]">
                {filteredCampaigns.map((c) => {
                  const campSent = c.stats?.sent || c.recipientCount || 1;
                  const campOpened = c.stats?.opened || 0;
                  const campClicked = c.stats?.clicked || 0;
                  const campOpenRate = ((campOpened / campSent) * 100).toFixed(0);
                  const campClickRate = ((campClicked / campSent) * 100).toFixed(0);

                  return (
                    <tr key={c.id} className="hover:bg-[#171A1D]/40 transition-colors">
                      <td className="py-3 px-4">
                        <Link
                          href={`/dashboard/campaigns/${c.id}`}
                          className="font-medium text-white hover:text-zinc-300 block"
                        >
                          {c.name}
                        </Link>
                        <span className="text-[11px] text-zinc-500 font-mono truncate block max-w-xs mt-0.5">
                          {c.subject}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-zinc-400 font-mono text-[11px]">
                        {formatDate(c.completedAt || c.createdAt)}
                      </td>
                      <td className="py-3 px-4 font-mono text-zinc-200">
                        {c.recipientCount}
                      </td>
                      <td className="py-3 px-4 font-mono text-emerald-400">
                        {c.stats?.delivered || 0}
                      </td>
                      <td className="py-3 px-4 font-mono text-white">
                        <div className="flex items-center gap-1.5">
                          <Eye className="w-3.5 h-3.5 text-zinc-400" />
                          <span>{campOpened}</span>
                          <span className="text-[10px] text-zinc-500">({campOpenRate}%)</span>
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-white">
                        <div className="flex items-center gap-1.5">
                          <MousePointerClick className="w-3.5 h-3.5 text-zinc-400" />
                          <span>{campClicked}</span>
                          <span className="text-[10px] text-zinc-500">({campClickRate}%)</span>
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-amber-400">
                        {c.stats?.bounced || 0}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <Link
                          href={`/dashboard/campaigns/${c.id}`}
                          className="text-xs font-mono text-zinc-400 hover:text-white inline-flex items-center justify-end gap-1"
                        >
                          <span>Report</span>
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
