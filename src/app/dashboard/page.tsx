"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/context/auth-context";
import { getCampaigns, getContacts } from "@/lib/store/db-service";
import { Campaign, Contact } from "@/types";
import { formatDate, formatNumber } from "@/lib/utils";
import { motion } from "motion/react";
import {
  Send,
  Users,
  Megaphone,
  ArrowUpRight,
  Plus,
  RefreshCw,
  Eye,
  Globe,
} from "lucide-react";
import { CountUp } from "@/components/motion/CountUp";

export default function DashboardOverviewPage() {
  const { user, profile } = useAuth();
  const userId = user?.uid || profile?.uid || "";

  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [loading, setLoading] = useState(true);

  const loadDashboardData = async (forceRefresh = false) => {
    if (!userId) return;
    setLoading(true);
    try {
      const [cmpList, cntList] = await Promise.all([
        getCampaigns(userId, forceRefresh),
        getContacts(userId, forceRefresh),
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
    if (!userId) return;
    loadDashboardData();
  }, [userId]);

  // Aggregate telemetry
  const totalEmailsSent = campaigns.reduce((acc, c) => acc + (c.stats?.sent || 0), 0);
  const totalDelivered = campaigns.reduce((acc, c) => acc + (c.stats?.delivered || 0), 0);
  const totalOpened = campaigns.reduce((acc, c) => acc + (c.stats?.opened || 0), 0);
  const totalClicked = campaigns.reduce((acc, c) => acc + (c.stats?.clicked || 0), 0);
  const totalFailed = campaigns.reduce((acc, c) => acc + (c.stats?.failed || 0), 0);
  const totalBounced = campaigns.reduce((acc, c) => acc + (c.stats?.bounced || 0), 0);
  const totalContacts = contacts.length;
  const activeContacts = contacts.filter((c) => c.status === "active").length;
  const totalCampaigns = campaigns.length;

  const deliveryRate = totalEmailsSent > 0 ? ((totalDelivered / totalEmailsSent) * 100).toFixed(1) : "0.0";
  const openRate = totalDelivered > 0 ? ((totalOpened / totalDelivered) * 100).toFixed(1) : "0.0";
  const clickRate = totalDelivered > 0 ? ((totalClicked / totalDelivered) * 100).toFixed(1) : "0.0";

  // Check if any campaign is actively sending
  const activeCampaign = campaigns.find((c) => ["sending", "queued"].includes(c.status));

  return (
    <div className="space-y-8 font-sans">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-6 border-b border-[#1C2024]">
        <div>
          <h1 className="text-2xl font-semibold tracking-[-0.02em] text-[#F5F5F5]">Overview</h1>
          <p className="text-xs text-[#A1A1AA] mt-1 font-mono">
            Telemetry, recipient engagement, and active email pipeline
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <motion.button
            whileHover={{ y: -1 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => loadDashboardData(true)}
            disabled={loading}
            className="p-2 text-[#A1A1AA] hover:text-white bg-[#111315] hover:bg-[#171A1D] border border-[#262A2E] hover:border-zinc-500 rounded-md transition-colors"
            title="Refresh statistics"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          </motion.button>
          <motion.div whileHover={{ y: -1 }} whileTap={{ scale: 0.97 }}>
            <Link
              href="/dashboard/compose"
              className="inline-flex items-center gap-2 px-3.5 py-1.5 bg-white hover:bg-[#E5E7EB] text-[#08090A] rounded-md text-xs font-semibold shadow-sm transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Campaign</span>
            </Link>
          </motion.div>
        </div>
      </div>

      {/* Active Campaign Live Card (If sending) */}
      {activeCampaign && (
        <motion.div
          initial={{ opacity: 0, y: -6 }}
          animate={{ opacity: 1, y: 0 }}
          className="p-4 rounded-lg bg-[#111315] border border-[#22C55E]/40 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
        >
          <div className="flex items-center gap-3">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#22C55E] opacity-75" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-[#22C55E]" />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-[#F5F5F5]">{activeCampaign.name}</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#102719] text-[#22C55E] border border-[#22C55E]/30">
                  AUTO-SENDING ACTIVE
                </span>
              </div>
              <p className="text-[11px] font-mono text-[#71717A] mt-0.5">
                Sent: {activeCampaign.stats?.sent || 0} / {activeCampaign.recipientCount} recipients
              </p>
            </div>
          </div>

          <Link
            href={`/dashboard/campaigns/${activeCampaign.id}`}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-[#171A1D] hover:bg-[#1D2125] text-white border border-[#262A2E] hover:border-zinc-500 transition-colors"
          >
            <span>Live Monitor</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </motion.div>
      )}

      {/* KPI Stats Grid with CountUp & Hover Lift */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Total Sent */}
        <div className="p-4 rounded-lg bg-[#111315] border border-[#262A2E] hover:border-zinc-500 hover:-translate-y-0.5 transition-all duration-200">
          <span className="text-[11px] font-mono uppercase text-[#71717A] block">Total Sent</span>
          <p className="text-2xl font-bold font-mono text-[#F5F5F5] mt-1">
            <CountUp value={totalEmailsSent} duration={1.2} />
          </p>
          <span className="text-[10px] text-[#71717A] font-mono mt-1 block">{totalCampaigns} campaigns</span>
        </div>

        {/* Confirmed Delivered */}
        <div className="p-4 rounded-lg bg-[#111315] border border-[#262A2E] hover:border-zinc-500 hover:-translate-y-0.5 transition-all duration-200">
          <span className="text-[11px] font-mono uppercase text-[#71717A] block">Delivered</span>
          <p className="text-2xl font-bold font-mono text-[#22C55E] mt-1">
            <CountUp value={totalDelivered} duration={1.2} />
          </p>
          <span className="text-[10px] text-[#22C55E] font-mono mt-1 block">{deliveryRate}% rate</span>
        </div>

        {/* Opened Emails */}
        <div className="p-4 rounded-lg bg-[#111315] border border-[#262A2E] hover:border-zinc-500 hover:-translate-y-0.5 transition-all duration-200">
          <span className="text-[11px] font-mono uppercase text-[#71717A] block">Opens</span>
          <p className="text-2xl font-bold font-mono text-white mt-1">
            <CountUp value={totalOpened} duration={1.2} />
          </p>
          <span className="text-[10px] text-[#71717A] font-mono mt-1 block">{openRate}% rate</span>
        </div>

        {/* Clicked Links */}
        <div className="p-4 rounded-lg bg-[#111315] border border-[#262A2E] hover:border-zinc-500 hover:-translate-y-0.5 transition-all duration-200">
          <span className="text-[11px] font-mono uppercase text-[#71717A] block">Clicks</span>
          <p className="text-2xl font-bold font-mono text-white mt-1">
            <CountUp value={totalClicked} duration={1.2} />
          </p>
          <span className="text-[10px] text-[#71717A] font-mono mt-1 block">{clickRate}% CTR</span>
        </div>

        {/* Failed / Bounced */}
        <div className="p-4 rounded-lg bg-[#111315] border border-[#262A2E] hover:border-zinc-500 hover:-translate-y-0.5 transition-all duration-200">
          <span className="text-[11px] font-mono uppercase text-[#71717A] block">Bounces / Fails</span>
          <p className="text-2xl font-bold font-mono text-[#F5F5F5] mt-1">
            <CountUp value={totalFailed + totalBounced} duration={1.0} />
          </p>
          <span className="text-[10px] text-[#71717A] font-mono mt-1 block">{totalBounced} bnc · {totalFailed} fail</span>
        </div>

        {/* Total Contacts */}
        <div className="p-4 rounded-lg bg-[#111315] border border-[#262A2E] hover:border-zinc-500 hover:-translate-y-0.5 transition-all duration-200">
          <span className="text-[11px] font-mono uppercase text-[#71717A] block">Audience</span>
          <p className="text-2xl font-bold font-mono text-[#F5F5F5] mt-1">
            <CountUp value={totalContacts} duration={1.2} />
          </p>
          <span className="text-[10px] text-[#71717A] font-mono mt-1 block">{activeContacts} active</span>
        </div>
      </div>

      {/* Main Split: Recent Campaigns Table & Quick Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Campaigns Table */}
        <div className="lg:col-span-2 rounded-xl bg-[#111315] border border-[#262A2E] overflow-hidden">
          <div className="px-5 py-4 border-b border-[#1C2024] flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-[#F5F5F5]">Recent Campaigns</h2>
              <p className="text-xs text-[#71717A]">Latest email dispatches and delivery statuses</p>
            </div>
            <Link
              href="/dashboard/campaigns"
              className="text-xs font-mono text-[#A1A1AA] hover:text-white flex items-center gap-1 transition-colors"
            >
              <span>View all</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {campaigns.length === 0 ? (
            <div className="p-12 text-center">
              <Megaphone className="w-8 h-8 text-[#45494E] mx-auto mb-3" />
              <h3 className="text-sm font-medium text-[#F5F5F5]">No campaigns yet</h3>
              <p className="text-xs text-[#71717A] mt-1 max-w-sm mx-auto">
                Create and dispatch your first campaign to begin reaching your audience.
              </p>
              <Link
                href="/dashboard/compose"
                className="mt-4 inline-flex items-center gap-2 px-3 py-1.5 bg-white text-[#08090A] rounded text-xs font-semibold hover:bg-[#E5E7EB] transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Create Campaign</span>
              </Link>
            </div>
          ) : (
            <div className="divide-y divide-[#1C2024]">
              {campaigns.slice(0, 5).map((cmp) => {
                const isDelivered = cmp.status === "completed";
                const isSending = ["sending", "queued"].includes(cmp.status);
                const isFailed = cmp.status === "failed";

                return (
                  <div
                    key={cmp.id}
                    className="p-4 hover:bg-[#171A1D]/70 transition-colors duration-150 flex items-center justify-between gap-4 group"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <Link
                          href={`/dashboard/campaigns/${cmp.id}`}
                          className="font-medium text-xs text-[#F5F5F5] group-hover:text-white transition-colors truncate"
                        >
                          {cmp.name}
                        </Link>
                        <span
                          className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border transition-colors ${
                            isDelivered
                              ? "bg-[#102719] text-[#22C55E] border-[#22C55E]/30"
                              : isSending
                              ? "bg-[#111315] text-[#60A5FA] border-[#60A5FA]/30"
                              : isFailed
                              ? "bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/30"
                              : "bg-[#171A1D] text-[#A1A1AA] border-[#262A2E]"
                          }`}
                        >
                          {cmp.status.replace("_", " ")}
                        </span>
                      </div>
                      <p className="text-[11px] text-[#71717A] truncate font-mono">
                        {cmp.subject} · {formatDate(cmp.createdAt)}
                      </p>
                    </div>

                    <div className="flex items-center gap-4 text-right shrink-0">
                      <div>
                        <span className="text-xs font-mono text-[#F5F5F5] block">
                          {formatNumber(cmp.recipientCount || cmp.stats?.total || 0)}
                        </span>
                        <span className="text-[10px] font-mono text-[#71717A] block">recipients</span>
                      </div>

                      <Link
                        href={`/dashboard/campaigns/${cmp.id}`}
                        className="p-1.5 text-[#71717A] hover:text-white hover:bg-[#1D2125] rounded transition-colors"
                        title="View report"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </Link>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Quick Actions & Infrastructure Status */}
        <div className="space-y-4">
          <div className="p-5 rounded-xl bg-[#111315] border border-[#262A2E] space-y-4">
            <h3 className="text-xs font-mono uppercase text-[#71717A] tracking-wider">Quick Actions</h3>
            
            <div className="space-y-2">
              <Link
                href="/dashboard/compose"
                className="flex items-center justify-between p-3 rounded-lg bg-[#0D0F11] hover:bg-[#171A1D] border border-[#1C2024] hover:border-[#262A2E] hover:translate-x-0.5 transition-all duration-150 group"
              >
                <div className="flex items-center gap-3">
                  <div className="w-7 h-7 rounded bg-[#171A1D] flex items-center justify-center text-white group-hover:scale-105 transition-transform">
                    <Send className="w-3.5 h-3.5" />
                  </div>
                  <div>
                    <span className="text-xs font-semibold text-[#F5F5F5] block group-hover:text-white transition-colors">
                      Compose Campaign
                    </span>
                    <span className="text-[11px] text-[#71717A] block">Send personalized batch emails</span>
                  </div>
                </div>
                <ArrowUpRight className="w-3.5 h-3.5 text-[#71717A] group-hover:text-white transition-colors" />
              </Link>

              <Link
                href="/dashboard/contacts"
                className="flex items-center justify-between p-3 rounded-lg bg-[#0D0F11] hover:bg-[#171A1D] border border-[#1C2024] hover:border-[#262A2E] hover:translate-x-0.5 transition-all duration-150 group"
              >
                <div className="flex items-center gap-3">
                  <div className="w-7 h-7 rounded bg-[#171A1D] flex items-center justify-center text-white group-hover:scale-105 transition-transform">
                    <Users className="w-3.5 h-3.5" />
                  </div>
                  <div>
                    <span className="text-xs font-semibold text-[#F5F5F5] block group-hover:text-white transition-colors">
                      Import Contacts
                    </span>
                    <span className="text-[11px] text-[#71717A] block">Upload CSV or XLSX file</span>
                  </div>
                </div>
                <ArrowUpRight className="w-3.5 h-3.5 text-[#71717A] group-hover:text-white transition-colors" />
              </Link>

              <Link
                href="/dashboard/domains"
                className="flex items-center justify-between p-3 rounded-lg bg-[#0D0F11] hover:bg-[#171A1D] border border-[#1C2024] hover:border-[#262A2E] hover:translate-x-0.5 transition-all duration-150 group"
              >
                <div className="flex items-center gap-3">
                  <div className="w-7 h-7 rounded bg-[#171A1D] flex items-center justify-center text-[#22C55E] group-hover:scale-105 transition-transform">
                    <Globe className="w-3.5 h-3.5" />
                  </div>
                  <div>
                    <span className="text-xs font-semibold text-[#F5F5F5] block group-hover:text-white transition-colors">
                      Verify Domain (DKIM)
                    </span>
                    <span className="text-[11px] text-[#71717A] block">SPF, DMARC & DNS keys</span>
                  </div>
                </div>
                <ArrowUpRight className="w-3.5 h-3.5 text-[#71717A] group-hover:text-white transition-colors" />
              </Link>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-[#0D0F11] border border-[#1C2024] space-y-2 text-xs font-mono text-[#71717A]">
            <div className="flex items-center justify-between">
              <span>Database Engine:</span>
              <span className="text-[#22C55E]">High-Availability Connected</span>
            </div>
            <div className="flex items-center justify-between">
              <span>Auth Provider:</span>
              <span className="text-[#F5F5F5]">Firebase Google OAuth</span>
            </div>
            <div className="flex items-center justify-between">
              <span>Queue Scheduler:</span>
              <span className="text-[#22C55E]">Continuous Auto-Resume</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
