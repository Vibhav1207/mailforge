"use client";

import React, { useState, useEffect } from "react";
import { apiFetch } from "@/lib/api-client";
import {
  Globe,
  Plus,
  CheckCircle2,
  AlertCircle,
  Clock,
  RefreshCw,
  Copy,
  Check,
  Trash2,
  ShieldCheck,
  Server,
  Info,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

interface DnsRecord {
  type: string;
  name: string;
  value: string;
  ttl: string;
  status: "verified" | "pending" | "failed";
  priority?: number;
  purpose: "DKIM" | "SPF" | "DMARC" | "MX";
}

interface DomainItem {
  id: string;
  domain: string;
  status: "verified" | "pending" | "failed";
  selector: string;
  publicKey: string;
  records: DnsRecord[];
  createdAt: string;
  updatedAt: string;
}

export default function DomainsPage() {
  const [domains, setDomains] = useState<DomainItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [addingDomain, setAddingDomain] = useState(false);
  const [newDomainInput, setNewDomainInput] = useState("");
  const [addError, setAddError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [expandedDomain, setExpandedDomain] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const fetchDomains = async () => {
    try {
      setLoading(true);
      const res = await apiFetch("/api/domains");
      const data = await res.json().catch(() => ({}));
      if (res.ok && Array.isArray(data.domains)) {
        setDomains(data.domains);
        if (data.domains.length > 0 && !expandedDomain) {
          setExpandedDomain(data.domains[0].id);
        }
      }
    } catch (err) {
      console.error("Error fetching domains:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDomains();
  }, []);

  const handleAddDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    setAddError("");

    const cleanDomain = newDomainInput
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .replace(/\/.*$/, "")
      .replace(/:\d+$/, "");

    if (!cleanDomain) {
      setAddError("Please enter a domain name.");
      return;
    }

    try {
      setSubmitting(true);
      const res = await apiFetch("/api/domains", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: cleanDomain }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.error || "Failed to add domain. Check format and try again.");
      }

      if (data.domain) {
        setDomains((prev) => [data.domain, ...prev]);
        setExpandedDomain(data.domain.id);
        setNewDomainInput("");
        setAddingDomain(false);
      }
    } catch (err: any) {
      setAddError(err?.message || "Failed to add domain. Check format and try again.");
    } finally {
      setSubmitting(false);
    }
  };

  const handleVerifyDns = async (domain: DomainItem) => {
    try {
      setVerifyingId(domain.id);
      const res = await apiFetch("/api/domains/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: domain.domain, domainId: domain.id }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.error || "Verification request failed.");
      }

      if (data.domain) {
        setDomains((prev) =>
          prev.map((d) => (d.id === domain.id ? data.domain : d))
        );
      }
    } catch (err: any) {
      alert(`Verification check: ${err?.message || "Could not reach DNS servers."}`);
    } finally {
      setVerifyingId(null);
    }
  };

  const handleDeleteDomain = async (domain: DomainItem) => {
    if (!window.confirm(`Are you sure you want to remove ${domain.domain}?`)) return;

    try {
      const res = await apiFetch(`/api/domains?id=${encodeURIComponent(domain.id)}`, {
        method: "DELETE",
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || "Failed to delete domain.");
      }
      setDomains((prev) => prev.filter((d) => d.id !== domain.id));
      if (expandedDomain === domain.id) setExpandedDomain(null);
    } catch (err: any) {
      alert(`Failed to delete: ${err?.message}`);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="space-y-6 pb-16">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#262A2E] pb-6">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-medium tracking-tight text-white">
              Sending Domains
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#171A1D] text-zinc-300 border border-[#262A2E]">
              DKIM & SPF RELAY
            </span>
          </div>
          <p className="text-xs text-zinc-400 font-mono mt-1">
            Authenticate your custom domain with 2048-bit DKIM keys and SPF verification records.
          </p>
        </div>

        <button
          onClick={() => setAddingDomain(true)}
          className="inline-flex items-center justify-center gap-2 px-4 py-1.5 text-xs font-medium text-black bg-white rounded-lg hover:bg-zinc-200 transition-colors shadow-sm"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Add Domain</span>
        </button>
      </div>

      {/* Add Domain Drawer */}
      {addingDomain && (
        <div className="bg-[#111315] border border-[#262A2E] rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-zinc-400" />
              <h2 className="text-sm font-medium text-white">Connect a Sending Domain</h2>
            </div>
            <button
              onClick={() => {
                setAddingDomain(false);
                setAddError("");
              }}
              className="text-zinc-500 hover:text-white text-xs font-mono"
            >
              Cancel
            </button>
          </div>

          <form onSubmit={handleAddDomain} className="space-y-4">
            <div>
              <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                Domain Name
              </label>
              <input
                type="text"
                placeholder="acme.com or mail.acme.com"
                value={newDomainInput}
                onChange={(e) => setNewDomainInput(e.target.value)}
                className="w-full px-3 py-2 bg-[#171A1D] border border-[#262A2E] rounded-lg text-xs text-white font-mono focus:border-zinc-500 focus:outline-none"
                disabled={submitting}
                autoFocus
              />
              <p className="text-[11px] text-zinc-500 font-mono mt-1">
                Postvane will generate an RSA-2048 DKIM keypair and DNS records for this domain.
              </p>
            </div>

            {addError && (
              <div className="flex items-center gap-2 p-3 text-xs text-red-400 bg-red-950/40 border border-red-500/30 rounded-lg font-mono">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{addError}</span>
              </div>
            )}

            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={() => setAddingDomain(false)}
                className="px-3.5 py-1.5 text-xs font-mono text-zinc-400 hover:text-white rounded-lg"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="inline-flex items-center gap-2 px-4 py-1.5 text-xs font-medium text-black bg-white hover:bg-zinc-200 rounded-lg disabled:opacity-50 transition-colors"
              >
                {submitting ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Generating Records...</span>
                  </>
                ) : (
                  "Generate DNS Records"
                )}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Domains List */}
      {loading ? (
        <div className="flex items-center justify-center p-12 bg-[#111315] rounded-xl border border-[#262A2E]">
          <div className="flex items-center gap-2 font-mono text-zinc-500 text-xs">
            <RefreshCw className="w-4 h-4 animate-spin text-white" />
            LOADING DOMAIN CONFIGURATIONS...
          </div>
        </div>
      ) : domains.length === 0 ? (
        <div className="text-center p-12 bg-[#111315] rounded-xl border border-dashed border-[#262A2E]">
          <Globe className="w-10 h-10 text-zinc-600 mx-auto mb-3" />
          <h3 className="text-sm font-medium text-white">No Custom Domains Connected</h3>
          <p className="text-xs text-zinc-400 font-mono max-w-md mx-auto mt-1 mb-5">
            Add your domain to generate 2048-bit DKIM keys and SPF verification records.
          </p>
          <button
            onClick={() => setAddingDomain(true)}
            className="inline-flex items-center gap-2 px-4 py-1.5 text-xs font-medium text-black bg-white rounded-lg hover:bg-zinc-200 transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Your First Domain</span>
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {domains.map((domain) => {
            const isExpanded = expandedDomain === domain.id;
            const isVerified = domain.status === "verified";
            const isVerifying = verifyingId === domain.id;

            return (
              <div
                key={domain.id}
                className="bg-[#111315] rounded-xl border border-[#262A2E] overflow-hidden transition-all"
              >
                {/* Domain Header Row */}
                <div className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#171A1D]/40">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg bg-[#111315] border border-[#262A2E] flex items-center justify-center text-zinc-400 shrink-0">
                      <Globe className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-white font-mono">
                          {domain.domain}
                        </span>
                        {isVerified ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono border border-emerald-500/30 bg-emerald-950/40 text-emerald-400">
                            <CheckCircle2 className="w-3 h-3" />
                            VERIFIED
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono border border-amber-500/30 bg-amber-950/40 text-amber-400">
                            <Clock className="w-3 h-3" />
                            PENDING DNS
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-zinc-500 font-mono mt-0.5">
                        Selector: <span className="text-zinc-300">{domain.selector || "pv1"}</span> • Added {new Date(domain.createdAt).toLocaleDateString()}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleVerifyDns(domain)}
                      disabled={isVerifying}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono text-zinc-300 bg-[#111315] border border-[#262A2E] rounded-lg hover:border-zinc-500 hover:text-white transition-colors disabled:opacity-50"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${isVerifying ? "animate-spin text-white" : ""}`} />
                      <span>{isVerifying ? "Verifying..." : "Verify DNS"}</span>
                    </button>

                    <button
                      onClick={() => handleDeleteDomain(domain)}
                      className="p-1.5 text-zinc-500 hover:text-red-400 hover:bg-[#111315] rounded-lg transition-colors"
                      title="Delete domain"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>

                    <button
                      onClick={() => setExpandedDomain(isExpanded ? null : domain.id)}
                      className="p-1.5 text-zinc-400 hover:text-white hover:bg-[#111315] rounded-lg transition-colors"
                      title={isExpanded ? "Collapse records" : "View DNS records"}
                    >
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Collapsible DNS Records Table */}
                {isExpanded && (
                  <div className="p-5 border-t border-[#262A2E] space-y-4">
                    <div>
                      <h4 className="text-xs font-mono uppercase tracking-wider text-zinc-400 mb-1">
                        Required DNS Configuration Records
                      </h4>
                      <p className="text-xs text-zinc-500 font-mono">
                        Add these records to your DNS provider (Cloudflare, Namecheap, Route 53, etc.), then click <strong>Verify DNS</strong>.
                      </p>
                    </div>

                    <div className="overflow-x-auto border border-[#262A2E] rounded-lg">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-[#171A1D] text-zinc-400 font-mono text-[11px] uppercase tracking-wider border-b border-[#262A2E]">
                          <tr>
                            <th className="py-2.5 px-3 font-medium">Type</th>
                            <th className="py-2.5 px-3 font-medium">Host / Name</th>
                            <th className="py-2.5 px-3 font-medium">Value / Target</th>
                            <th className="py-2.5 px-3 font-medium">Protocol</th>
                            <th className="py-2.5 px-3 text-right font-medium">Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#1C2024] font-mono">
                          {domain.records?.map((record, idx) => {
                            const nameKey = `${domain.id}-name-${idx}`;
                            const valKey = `${domain.id}-val-${idx}`;

                            return (
                              <tr key={idx} className="hover:bg-[#171A1D]/40 transition-colors">
                                <td className="py-3 px-3 text-white font-medium">
                                  {record.type}
                                </td>
                                <td className="py-3 px-3 max-w-[200px]">
                                  <div className="flex items-center gap-1.5">
                                    <span className="truncate select-all text-zinc-200" title={record.name}>
                                      {record.name}
                                    </span>
                                    <button
                                      onClick={() => copyToClipboard(record.name, nameKey)}
                                      className="text-zinc-500 hover:text-white shrink-0"
                                      title="Copy Host"
                                    >
                                      {copiedKey === nameKey ? (
                                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                                      ) : (
                                        <Copy className="w-3.5 h-3.5" />
                                      )}
                                    </button>
                                  </div>
                                </td>
                                <td className="py-3 px-3 max-w-[340px]">
                                  <div className="flex items-center gap-1.5">
                                    <span
                                      className="truncate select-all text-zinc-400 text-[11px]"
                                      title={record.value}
                                    >
                                      {record.value}
                                    </span>
                                    <button
                                      onClick={() => copyToClipboard(record.value, valKey)}
                                      className="text-zinc-500 hover:text-white shrink-0"
                                      title="Copy Value"
                                    >
                                      {copiedKey === valKey ? (
                                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                                      ) : (
                                        <Copy className="w-3.5 h-3.5" />
                                      )}
                                    </button>
                                  </div>
                                </td>
                                <td className="py-3 px-3 font-mono">
                                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-[#171A1D] border border-[#262A2E] text-zinc-300">
                                    {record.purpose}
                                  </span>
                                </td>
                                <td className="py-3 px-3 text-right font-mono">
                                  {record.status === "verified" ? (
                                    <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400">
                                      <CheckCircle2 className="w-3 h-3" />
                                      Active
                                    </span>
                                  ) : (
                                    <span className="inline-flex items-center gap-1 text-[11px] text-amber-400">
                                      <Clock className="w-3 h-3" />
                                      Pending
                                    </span>
                                  )}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>

                    <div className="p-3 bg-[#171A1D] border border-[#262A2E] rounded-lg flex items-start gap-2.5 text-xs text-zinc-400 font-mono">
                      <Info className="w-4 h-4 text-zinc-400 shrink-0 mt-0.5" />
                      <div>
                        DNS changes typically propagate worldwide within 2 to 15 minutes.
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Feature Explainer Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
        <div className="bg-[#111315] p-5 rounded-xl border border-[#262A2E]">
          <div className="w-8 h-8 rounded-lg bg-[#171A1D] border border-[#262A2E] text-zinc-300 flex items-center justify-center mb-3">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <h4 className="text-xs font-mono uppercase tracking-wider text-white mb-1">DKIM Signing</h4>
          <p className="text-xs text-zinc-400 leading-relaxed font-mono">
            Cryptographic RSA-2048 signing on all outgoing MTA messages prevents spoofing and ensures inbox delivery.
          </p>
        </div>

        <div className="bg-[#111315] p-5 rounded-xl border border-[#262A2E]">
          <div className="w-8 h-8 rounded-lg bg-[#171A1D] border border-[#262A2E] text-zinc-300 flex items-center justify-center mb-3">
            <Server className="w-4 h-4" />
          </div>
          <h4 className="text-xs font-mono uppercase tracking-wider text-white mb-1">Direct DNS Queries</h4>
          <p className="text-xs text-zinc-400 leading-relaxed font-mono">
            Postvane directly queries root resolvers (8.8.8.8 and 1.1.1.1) to verify SPF, DMARC, and DKIM public records.
          </p>
        </div>

        <div className="bg-[#111315] p-5 rounded-xl border border-[#262A2E]">
          <div className="w-8 h-8 rounded-lg bg-[#171A1D] border border-[#262A2E] text-zinc-300 flex items-center justify-center mb-3">
            <Globe className="w-4 h-4" />
          </div>
          <h4 className="text-xs font-mono uppercase tracking-wider text-white mb-1">Self-Hosted Freedom</h4>
          <p className="text-xs text-zinc-400 leading-relaxed font-mono">
            Send from any verified domain via Gmail App Passwords, custom SMTP servers, or developer APIs.
          </p>
        </div>
      </div>
    </div>
  );
}
