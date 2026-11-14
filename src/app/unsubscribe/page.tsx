"use client";

import React, { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { CheckCircle2, AlertCircle, ShieldAlert } from "lucide-react";

function UnsubscribeContent() {
  const searchParams = useSearchParams();
  const emailParam = searchParams.get("email") || "";
  const campaignIdParam = searchParams.get("cid") || "";

  const [email, setEmail] = useState(emailParam);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (emailParam) setEmail(emailParam);
  }, [emailParam]);

  const handleUnsubscribe = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;

    setLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/unsubscribe", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          campaignId: campaignIdParam,
          reason: "User confirmed on unsubscribe page",
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to unsubscribe");
      }
      setSuccess(true);
    } catch (err: any) {
      setError(err.message || "An error occurred");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#08090A] text-[#F5F5F5] flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md text-center">
        <div className="inline-flex items-center justify-center w-10 h-10 rounded-lg bg-white text-black font-bold text-sm mb-4">
          <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="m22 2-7 20-4-9-9-4Z" />
            <path d="M22 2 11 13" />
          </svg>
        </div>
        <h2 className="text-xl font-medium tracking-tight text-white">
          Email Preferences & Opt-Out
        </h2>
        <p className="mt-1 text-xs text-zinc-400 font-mono">
          We honor suppression requests immediately across all sending channels.
        </p>
      </div>

      <div className="mt-6 sm:mx-auto sm:w-full sm:max-w-md px-4 sm:px-0">
        <div className="bg-[#111315] py-8 px-6 border border-[#262A2E] rounded-xl sm:px-10">
          {success ? (
            <div className="text-center py-4">
              <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
              <h3 className="text-base font-medium text-white">You have been unsubscribed</h3>
              <p className="mt-2 text-xs text-zinc-400 font-mono">
                <strong className="text-zinc-200">{email}</strong> has been added to our suppression table. You will no longer receive campaigns from this sender.
              </p>
              <div className="mt-6 pt-4 border-t border-[#262A2E] text-[11px] text-zinc-500 font-mono">
                CAN-SPAM and GDPR RFC 8058 compliant suppression enforced.
              </div>
            </div>
          ) : (
            <form onSubmit={handleUnsubscribe} className="space-y-4">
              {error && (
                <div className="p-3 rounded-lg bg-red-950/40 border border-red-500/30 text-red-400 text-xs flex items-center gap-2 font-mono">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <div>
                <label className="block text-[11px] font-mono text-zinc-400 mb-1.5 uppercase tracking-wider">
                  Email Address
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  placeholder="name@example.com"
                  className="w-full px-3 py-2 text-xs bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:outline-none focus:border-zinc-500 font-mono"
                />
              </div>

              <div className="p-3 bg-[#171A1D] border border-[#262A2E] rounded-lg text-xs text-zinc-400 flex items-start gap-2 font-mono">
                <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <span>
                  Confirming will permanently suppress this address from future broadcast dispatches.
                </span>
              </div>

              <button
                type="submit"
                disabled={loading || !email}
                className="w-full py-2.5 px-4 bg-white hover:bg-zinc-200 text-black font-medium text-xs rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed font-sans"
              >
                {loading ? "Processing..." : "Unsubscribe My Address"}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}

export default function UnsubscribePage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-[#08090A] text-zinc-500 font-mono text-xs flex items-center justify-center">Loading...</div>}>
      <UnsubscribeContent />
    </Suspense>
  );
}
