"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/context/auth-context";
import {
  Send,
  ShieldCheck,
  CheckCircle2,
  Users,
  Gauge,
  BarChart3,
  ArrowRight,
  Sparkles,
  Lock,
  Globe,
  Key,
  FileCode2,
  Check,
  Mail,
  Zap,
  ChevronRight,
  TrendingUp,
  Clock,
  Layers,
  Terminal,
} from "lucide-react";

export default function LandingPage() {
  const { user, profile, loading, isFirebaseActive, signInWithGoogle } = useAuth();
  const [signingIn, setSigningIn] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);

  useEffect(() => {
    if (!loading && (user || profile)) {
      window.location.href = "/dashboard";
    }
  }, [user, profile, loading]);

  const handleGoogleLogin = async () => {
    setAuthError(null);
    setSigningIn(true);
    try {
      await signInWithGoogle();
      window.location.href = "/dashboard";
    } catch (err: any) {
      if (err?.code === "auth/popup-closed-by-user") {
        setAuthError("Sign-in popup was closed before completing.");
      } else {
        setAuthError(err?.message || "Google sign-in failed. Please verify credentials.");
      }
    } finally {
      setSigningIn(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#08090A] text-[#F5F5F5] flex flex-col font-sans selection:bg-white/10 selection:text-white">
      {/* Top Banner / Announcement */}
      <div className="border-b border-[#1C2024] bg-[#0D0F11]/60 px-4 py-2 text-center text-xs text-[#A1A1AA] flex items-center justify-center gap-2">
        <span className="w-1.5 h-1.5 rounded-full bg-[#22C55E]" />
        <span>Postvane v3.0 is live: Native DKIM signing, high-speed MongoDB indexing & continuous auto-resume.</span>
      </div>

      {/* Navigation */}
      <header className="sticky top-0 z-50 border-b border-[#1C2024] bg-[#08090A]/90 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          {/* Logo & Wordmark */}
          <Link href="/" className="flex items-center gap-2.5 group">
            <div className="w-7 h-7 rounded-md bg-white flex items-center justify-center text-[#08090A] shadow-sm transition-transform group-hover:scale-105">
              <Mail className="w-4 h-4 fill-current" />
            </div>
            <span className="font-semibold text-base text-[#F5F5F5] tracking-tight">Postvane</span>
          </Link>

          {/* Navigation Links */}
          <nav className="hidden md:flex items-center gap-8 text-sm text-[#A1A1AA]">
            <a href="#features" className="hover:text-white transition-colors">Features</a>
            <a href="#workflow" className="hover:text-white transition-colors">Workflow</a>
            <a href="#security" className="hover:text-white transition-colors">Security</a>
            <Link href="/dashboard" className="hover:text-white transition-colors">Console</Link>
          </nav>

          {/* Auth Actions */}
          <div className="flex items-center gap-3">
            <button
              onClick={handleGoogleLogin}
              disabled={signingIn || loading}
              className="inline-flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium text-[#F5F5F5] hover:text-white bg-[#111315] hover:bg-[#171A1D] border border-[#262A2E] rounded-md transition-all shadow-sm"
            >
              Sign In
            </button>
            <button
              onClick={handleGoogleLogin}
              disabled={signingIn || loading}
              className="inline-flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold text-[#08090A] bg-white hover:bg-[#E5E7EB] rounded-md transition-all shadow-sm disabled:opacity-60"
            >
              <svg className="w-3.5 h-3.5 fill-current" viewBox="0 0 24 24">
                <path d="M12.24 10.285V14.4h6.806c-.275 1.765-2.056 5.174-6.806 5.174-4.095 0-7.439-3.389-7.439-7.574s3.345-7.574 7.439-7.574c2.33 0 3.891.989 4.785 1.849l3.254-3.138C18.189 1.186 15.479 0 12.24 0c-6.635 0-12 5.365-12 12s5.365 12 12 12c6.926 0 11.52-4.869 11.52-11.726 0-.788-.085-1.39-.189-1.989H12.24z" />
              </svg>
              <span>{signingIn ? "Connecting..." : "Get Started"}</span>
            </button>
          </div>
        </div>
      </header>

      {/* Hero Section (2-Column Grid) */}
      <section className="relative overflow-hidden pt-16 pb-20 md:pt-24 md:pb-28 border-b border-[#1C2024]">
        <div className="max-w-7xl mx-auto px-6 grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-14 items-center">
          
          {/* Left Column: Headline & Value Proposition */}
          <div className="lg:col-span-5 flex flex-col items-start text-left">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-[#111315] border border-[#262A2E] text-[11px] font-mono uppercase tracking-wider text-[#A1A1AA] mb-6">
              <span className="w-1.5 h-1.5 rounded-full bg-[#22C55E]" />
              <span>EMAIL MARKETING PLATFORM</span>
            </div>

            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-semibold tracking-[-0.03em] text-[#F5F5F5] leading-[1.08] mb-6">
              Send email campaigns that <span className="text-white underline decoration-[#262A2E] underline-offset-8">actually deliver</span>.
            </h1>

            <p className="text-base sm:text-lg text-[#A1A1AA] leading-relaxed mb-8 max-w-xl">
              A developer-friendly platform to run, automate, and scale your email outreach — with granular control, verified deliverability, and real-time engagement telemetry.
            </p>

            {authError && (
              <div className="mb-6 p-3 text-xs text-[#EF4444] bg-[#EF4444]/10 border border-[#EF4444]/20 rounded-md">
                {authError}
              </div>
            )}

            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 w-full sm:w-auto mb-10">
              <button
                onClick={handleGoogleLogin}
                disabled={signingIn || loading}
                className="inline-flex items-center justify-center gap-2.5 px-5 py-2.5 text-sm font-semibold text-[#08090A] bg-white hover:bg-[#E5E7EB] rounded-md transition-all shadow-sm active:scale-[0.99] disabled:opacity-60"
              >
                <svg className="w-4 h-4 fill-current" viewBox="0 0 24 24">
                  <path d="M12.24 10.285V14.4h6.806c-.275 1.765-2.056 5.174-6.806 5.174-4.095 0-7.439-3.389-7.439-7.574s3.345-7.574 7.439-7.574c2.33 0 3.891.989 4.785 1.849l3.254-3.138C18.189 1.186 15.479 0 12.24 0c-6.635 0-12 5.365-12 12s5.365 12 12 12c6.926 0 11.52-4.869 11.52-11.726 0-.788-.085-1.39-.189-1.989H12.24z" />
                </svg>
                <span>{signingIn ? "Authenticating..." : "Get started with Google"}</span>
              </button>

              <a
                href="#features"
                className="inline-flex items-center justify-center gap-2 px-5 py-2.5 text-sm font-medium text-[#A1A1AA] hover:text-white bg-[#111315] hover:bg-[#171A1D] border border-[#262A2E] rounded-md transition-colors"
              >
                <span>View features</span>
                <ArrowRight className="w-4 h-4" />
              </a>
            </div>

            {/* Three Value Pillars */}
            <div className="grid grid-cols-3 gap-6 pt-6 border-t border-[#1C2024] w-full text-left">
              <div>
                <div className="flex items-center gap-1.5 text-xs font-semibold text-[#F5F5F5] mb-1">
                  <Send className="w-3.5 h-3.5 text-white" />
                  <span>Bulk sending</span>
                </div>
                <p className="text-[11px] text-[#71717A] leading-normal">
                  Zero queue lockups with smart auto-resume.
                </p>
              </div>

              <div>
                <div className="flex items-center gap-1.5 text-xs font-semibold text-[#F5F5F5] mb-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-[#22C55E]" />
                  <span>Deliverability</span>
                </div>
                <p className="text-[11px] text-[#71717A] leading-normal">
                  SPF, DKIM, and DMARC verified pipelines.
                </p>
              </div>

              <div>
                <div className="flex items-center gap-1.5 text-xs font-semibold text-[#F5F5F5] mb-1">
                  <ShieldCheck className="w-3.5 h-3.5 text-white" />
                  <span>Secure relay</span>
                </div>
                <p className="text-[11px] text-[#71717A] leading-normal">
                  AES-256 credentials & scoped rate limiting.
                </p>
              </div>
            </div>
          </div>

          {/* Right Column: Realistic Developer Dashboard Preview */}
          <div className="lg:col-span-7">
            <div className="rounded-xl border border-[#262A2E] bg-[#0D0F11] shadow-2xl overflow-hidden font-sans">
              
              {/* App Shell Mock Top Bar */}
              <div className="px-4 py-3 bg-[#111315] border-b border-[#262A2E] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#262A2E]" />
                  <span className="w-2.5 h-2.5 rounded-full bg-[#262A2E]" />
                  <span className="w-2.5 h-2.5 rounded-full bg-[#262A2E]" />
                  <span className="ml-3 text-xs font-mono text-[#71717A]">app.postvane.com/dashboard</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono bg-[#102719] text-[#22C55E] border border-[#22C55E]/30">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#22C55E] animate-pulse" />
                    LIVE TELEMETRY
                  </span>
                </div>
              </div>

              {/* Inside Dashboard Layout */}
              <div className="p-6 space-y-6">
                
                {/* Header Row */}
                <div className="flex items-center justify-between pb-4 border-b border-[#1C2024]">
                  <div>
                    <h2 className="text-base font-semibold text-[#F5F5F5]">Campaign Performance</h2>
                    <p className="text-xs text-[#71717A]">Real-time engagement telemetry across active dispatches</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-[#A1A1AA] bg-[#111315] px-2.5 py-1 rounded border border-[#262A2E]">
                      Region: us-east-1
                    </span>
                  </div>
                </div>

                {/* 4 Stats Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="p-3.5 rounded-lg bg-[#111315] border border-[#262A2E]">
                    <span className="text-[11px] font-mono text-[#71717A] uppercase">Emails Sent</span>
                    <p className="text-xl font-bold font-mono text-[#F5F5F5] mt-1">48,250</p>
                    <span className="text-[10px] text-[#22C55E] font-mono">+12.4% vs last week</span>
                  </div>

                  <div className="p-3.5 rounded-lg bg-[#111315] border border-[#262A2E]">
                    <span className="text-[11px] font-mono text-[#71717A] uppercase">Delivered</span>
                    <p className="text-xl font-bold font-mono text-[#22C55E] mt-1">99.3%</p>
                    <span className="text-[10px] text-[#71717A] font-mono">47,910 delivered</span>
                  </div>

                  <div className="p-3.5 rounded-lg bg-[#111315] border border-[#262A2E]">
                    <span className="text-[11px] font-mono text-[#71717A] uppercase">Open Rate</span>
                    <p className="text-xl font-bold font-mono text-white mt-1">42.8%</p>
                    <span className="text-[10px] text-[#71717A] font-mono">20,505 unique opens</span>
                  </div>

                  <div className="p-3.5 rounded-lg bg-[#111315] border border-[#262A2E]">
                    <span className="text-[11px] font-mono text-[#71717A] uppercase">Click Rate</span>
                    <p className="text-xl font-bold font-mono text-white mt-1">8.4%</p>
                    <span className="text-[10px] text-[#71717A] font-mono">4,028 tracked links</span>
                  </div>
                </div>

                {/* Active Campaign Dispatch Card */}
                <div className="p-4 rounded-lg bg-[#111315] border border-[#262A2E] space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-[#22C55E] animate-ping" />
                      <span className="text-xs font-semibold text-[#F5F5F5]">Active Send: Q4 Product Launch Announcement</span>
                    </div>
                    <span className="text-xs font-mono text-[#22C55E] bg-[#102719] px-2 py-0.5 rounded border border-[#22C55E]/30">
                      Sending: 1,880 / 2,000
                    </span>
                  </div>

                  {/* Progress Bar */}
                  <div className="w-full h-1.5 bg-[#171A1D] rounded-full overflow-hidden">
                    <div className="h-full bg-white rounded-full transition-all duration-500" style={{ width: "94%" }} />
                  </div>

                  <div className="flex items-center justify-between text-[11px] text-[#71717A] font-mono">
                    <span>Relay: smtp.gmail.com · TLS 1.3</span>
                    <span>Rate: 5 msg/sec · 0 dropped</span>
                  </div>
                </div>

                {/* Recent Dispatches Mini Table */}
                <div className="rounded-lg border border-[#262A2E] overflow-hidden">
                  <div className="px-3.5 py-2 bg-[#171A1D] border-b border-[#262A2E] text-[11px] font-mono uppercase text-[#71717A] grid grid-cols-12 gap-2">
                    <span className="col-span-5">Campaign Name</span>
                    <span className="col-span-3">Recipients</span>
                    <span className="col-span-2">Open Rate</span>
                    <span className="col-span-2 text-right">Status</span>
                  </div>

                  <div className="divide-y divide-[#1C2024] text-xs bg-[#111315]">
                    <div className="px-3.5 py-2.5 grid grid-cols-12 gap-2 items-center">
                      <span className="col-span-5 text-[#F5F5F5] font-medium truncate">Early Beta Invites — Tier 1</span>
                      <span className="col-span-3 font-mono text-[#A1A1AA]">4,500</span>
                      <span className="col-span-2 font-mono text-[#22C55E]">51.2%</span>
                      <span className="col-span-2 text-right">
                        <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#102719] text-[#22C55E]">Delivered</span>
                      </span>
                    </div>

                    <div className="px-3.5 py-2.5 grid grid-cols-12 gap-2 items-center">
                      <span className="col-span-5 text-[#F5F5F5] font-medium truncate">Security Advisory Notice (CVE-2026)</span>
                      <span className="col-span-3 font-mono text-[#A1A1AA]">12,800</span>
                      <span className="col-span-2 font-mono text-[#22C55E]">68.9%</span>
                      <span className="col-span-2 text-right">
                        <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#102719] text-[#22C55E]">Delivered</span>
                      </span>
                    </div>

                    <div className="px-3.5 py-2.5 grid grid-cols-12 gap-2 items-center">
                      <span className="col-span-5 text-[#F5F5F5] font-medium truncate">Weekly Developer Digest #48</span>
                      <span className="col-span-3 font-mono text-[#A1A1AA]">18,200</span>
                      <span className="col-span-2 font-mono text-[#22C55E]">44.1%</span>
                      <span className="col-span-2 text-right">
                        <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#102719] text-[#22C55E]">Delivered</span>
                      </span>
                    </div>
                  </div>
                </div>

              </div>
            </div>
          </div>

        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 md:py-28 border-b border-[#1C2024] bg-[#0D0F11]">
        <div className="max-w-7xl mx-auto px-6">
          <div className="max-w-2xl mb-16">
            <h2 className="text-3xl sm:text-4xl font-semibold tracking-[-0.03em] text-[#F5F5F5] mb-4">
              Everything you need to run email campaigns.
            </h2>
            <p className="text-base text-[#A1A1AA] leading-relaxed">
              Purpose-built email marketing infrastructure designed for reliability, high deliverability, and developer control.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {/* Feature 1 */}
            <div className="p-6 rounded-xl bg-[#111315] border border-[#262A2E] hover:border-[#45494E] transition-colors">
              <div className="w-10 h-10 rounded-lg bg-[#171A1D] border border-[#262A2E] flex items-center justify-center text-white mb-5">
                <Send className="w-5 h-5" />
              </div>
              <h3 className="text-base font-semibold text-[#F5F5F5] mb-2">Bulk & Scheduled Sending</h3>
              <p className="text-sm text-[#A1A1AA] leading-relaxed">
                Send thousands of emails reliably, with control. Background retry engines and automated execution windows ensure 100% completion.
              </p>
            </div>

            {/* Feature 2 */}
            <div className="p-6 rounded-xl bg-[#111315] border border-[#262A2E] hover:border-[#45494E] transition-colors">
              <div className="w-10 h-10 rounded-lg bg-[#171A1D] border border-[#262A2E] flex items-center justify-center text-white mb-5">
                <Users className="w-5 h-5" />
              </div>
              <h3 className="text-base font-semibold text-[#F5F5F5] mb-2">Contact Management</h3>
              <p className="text-sm text-[#A1A1AA] leading-relaxed">
                Import via CSV, map fields, and organize your audience. Instant parsing, deduplication, and custom tag categorization.
              </p>
            </div>

            {/* Feature 3 */}
            <div className="p-6 rounded-xl bg-[#111315] border border-[#262A2E] hover:border-[#45494E] transition-colors">
              <div className="w-10 h-10 rounded-lg bg-[#171A1D] border border-[#262A2E] flex items-center justify-center text-white mb-5">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <h3 className="text-base font-semibold text-[#F5F5F5] mb-2">Throttling & Safety</h3>
              <p className="text-sm text-[#A1A1AA] leading-relaxed">
                Built-in rate limiting and suppression for better delivery. Automated unsubscribes, bounce protection, and RFC-compliant headers.
              </p>
            </div>

            {/* Feature 4 */}
            <div className="p-6 rounded-xl bg-[#111315] border border-[#262A2E] hover:border-[#45494E] transition-colors">
              <div className="w-10 h-10 rounded-lg bg-[#171A1D] border border-[#262A2E] flex items-center justify-center text-white mb-5">
                <BarChart3 className="w-5 h-5" />
              </div>
              <h3 className="text-base font-semibold text-[#F5F5F5] mb-2">Real-time Analytics</h3>
              <p className="text-sm text-[#A1A1AA] leading-relaxed">
                Track opens, clicks, and campaign performance. Cryptographically signed tracking pixels and link proxies with detailed delivery logs.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Workflow Section (01 - 04) */}
      <section id="workflow" className="py-20 md:py-28 border-b border-[#1C2024] bg-[#08090A]">
        <div className="max-w-7xl mx-auto px-6">
          <div className="max-w-xl mb-16">
            <span className="text-xs font-mono uppercase tracking-wider text-[#71717A]">WORKFLOW</span>
            <h2 className="text-3xl sm:text-4xl font-semibold tracking-[-0.03em] text-[#F5F5F5] mt-2 mb-4">
              How Postvane works
            </h2>
            <p className="text-base text-[#A1A1AA]">
              Four seamless steps from contact import to real-time delivery telemetry.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            <div className="p-5 rounded-lg bg-[#0D0F11] border border-[#1C2024] relative">
              <span className="text-xs font-mono text-[#71717A]">01</span>
              <h3 className="text-sm font-semibold text-[#F5F5F5] mt-3 mb-1">Import contacts</h3>
              <p className="text-xs text-[#A1A1AA] leading-normal">
                Upload CSV or Excel files with instant column mapping and validation.
              </p>
            </div>

            <div className="p-5 rounded-lg bg-[#0D0F11] border border-[#1C2024] relative">
              <span className="text-xs font-mono text-[#71717A]">02</span>
              <h3 className="text-sm font-semibold text-[#F5F5F5] mt-3 mb-1">Build your campaign</h3>
              <p className="text-xs text-[#A1A1AA] leading-normal">
                Craft HTML or rich text with dynamic {"{{variable}}"} personalization tags.
              </p>
            </div>

            <div className="p-5 rounded-lg bg-[#0D0F11] border border-[#1C2024] relative">
              <span className="text-xs font-mono text-[#71717A]">03</span>
              <h3 className="text-sm font-semibold text-[#F5F5F5] mt-3 mb-1">Configure delivery</h3>
              <p className="text-xs text-[#A1A1AA] leading-normal">
                Connect Gmail App Password or custom SMTP relays with DKIM signing.
              </p>
            </div>

            <div className="p-5 rounded-lg bg-[#0D0F11] border border-[#1C2024] relative">
              <span className="text-xs font-mono text-[#71717A]">04</span>
              <h3 className="text-sm font-semibold text-[#F5F5F5] mt-3 mb-1">Send and monitor</h3>
              <p className="text-xs text-[#A1A1AA] leading-normal">
                Dispatches run with continuous auto-resume and live open/click metrics.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Security Architecture */}
      <section id="security" className="py-20 md:py-28 border-b border-[#1C2024] bg-[#0D0F11]">
        <div className="max-w-7xl mx-auto px-6">
          <div className="max-w-xl mb-16">
            <span className="text-xs font-mono uppercase tracking-wider text-[#71717A]">SECURITY ARCHITECTURE</span>
            <h2 className="text-3xl sm:text-4xl font-semibold tracking-[-0.03em] text-[#F5F5F5] mt-2 mb-4">
              Engineered for enterprise trust
            </h2>
            <p className="text-base text-[#A1A1AA]">
              Every layer of Postvane is hardened with strict cryptography, isolation, and access controls.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="p-6 rounded-xl bg-[#111315] border border-[#262A2E]">
              <div className="flex items-center gap-2 mb-3">
                <Lock className="w-4 h-4 text-white" />
                <h3 className="text-sm font-semibold text-[#F5F5F5]">Encrypted Credentials</h3>
              </div>
              <p className="text-xs text-[#A1A1AA] leading-relaxed">
                SMTP and Gmail app passwords are encrypted server-side with AES-256-GCM. Passwords are never sent to the browser in plaintext.
              </p>
            </div>

            <div className="p-6 rounded-xl bg-[#111315] border border-[#262A2E]">
              <div className="flex items-center gap-2 mb-3">
                <Globe className="w-4 h-4 text-[#22C55E]" />
                <h3 className="text-sm font-semibold text-[#F5F5F5]">DKIM & DNS Verification</h3>
              </div>
              <p className="text-xs text-[#A1A1AA] leading-relaxed">
                Native RSA-2048 DKIM key generator, SPF record audits, and DMARC alignment ensure sender legitimacy and spam-filter bypass.
              </p>
            </div>

            <div className="p-6 rounded-xl bg-[#111315] border border-[#262A2E]">
              <div className="flex items-center gap-2 mb-3">
                <ShieldCheck className="w-4 h-4 text-white" />
                <h3 className="text-sm font-semibold text-[#F5F5F5]">Suppression & Rate Limits</h3>
              </div>
              <p className="text-xs text-[#A1A1AA] leading-relaxed">
                Automatic suppression ensures unsubscribed contacts cannot be emailed again. Bounded concurrency protects your SMTP reputation.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Final CTA Section */}
      <section className="py-20 md:py-28 bg-[#08090A] text-center border-b border-[#1C2024]">
        <div className="max-w-3xl mx-auto px-6">
          <h2 className="text-3xl sm:text-5xl font-semibold tracking-[-0.03em] text-[#F5F5F5] mb-5">
            Ready to take control of your email campaigns?
          </h2>
          <p className="text-base text-[#A1A1AA] leading-relaxed max-w-xl mx-auto mb-8">
            Everything you need to send, manage, and monitor email campaigns from one place.
          </p>

          <button
            onClick={handleGoogleLogin}
            disabled={signingIn || loading}
            className="inline-flex items-center gap-2.5 px-6 py-3 text-sm font-semibold text-[#08090A] bg-white hover:bg-[#E5E7EB] rounded-md transition-all shadow-sm disabled:opacity-60"
          >
            <svg className="w-4 h-4 fill-current" viewBox="0 0 24 24">
              <path d="M12.24 10.285V14.4h6.806c-.275 1.765-2.056 5.174-6.806 5.174-4.095 0-7.439-3.389-7.439-7.574s3.345-7.574 7.439-7.574c2.33 0 3.891.989 4.785 1.849l3.254-3.138C18.189 1.186 15.479 0 12.24 0c-6.635 0-12 5.365-12 12s5.365 12 12 12c6.926 0 11.52-4.869 11.52-11.726 0-.788-.085-1.39-.189-1.989H12.24z" />
            </svg>
            <span>Get started with Google</span>
          </button>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 bg-[#08090A] text-xs text-[#71717A]">
        <div className="max-w-7xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-2.5">
            <div className="w-5 h-5 rounded bg-white flex items-center justify-center text-[#08090A] font-bold">
              <Mail className="w-3 h-3 fill-current" />
            </div>
            <span className="font-semibold text-sm text-[#F5F5F5] tracking-tight">Postvane</span>
            <span className="text-[#45494E]">·</span>
            <span>Developer-First Email Platform</span>
          </div>

          <div className="flex items-center gap-6 text-[#A1A1AA]">
            <a href="#features" className="hover:text-white transition-colors">Features</a>
            <a href="#workflow" className="hover:text-white transition-colors">Workflow</a>
            <a href="#security" className="hover:text-white transition-colors">Security</a>
            <a href="https://github.com/Vibhav1207/mailforge" target="_blank" rel="noreferrer" className="hover:text-white transition-colors">GitHub</a>
          </div>

          <div>
            <span>© {new Date().getFullYear()} Postvane Inc. All rights reserved.</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
