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
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
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
      if (res.domains) {
        setDomains(res.domains);
        if (res.domains.length > 0 && !expandedDomain) {
          setExpandedDomain(res.domains[0].id);
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
    if (!newDomainInput.trim()) return;

    try {
      setSubmitting(true);
      const res = await apiFetch("/api/domains", {
        method: "POST",
        body: JSON.stringify({ domain: newDomainInput }),
      });

      if (res.success && res.domain) {
        setDomains((prev) => [res.domain, ...prev]);
        setExpandedDomain(res.domain.id);
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
        body: JSON.stringify({ domain: domain.domain, domainId: domain.id }),
      });

      if (res.domain) {
        setDomains((prev) =>
          prev.map((d) => (d.id === domain.id ? res.domain : d))
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
      await apiFetch(`/api/domains?id=${encodeURIComponent(domain.id)}`, {
        method: "DELETE",
      });
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
    <div className="max-w-6xl mx-auto space-y-8 pb-16">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-200 pb-6">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-slate-900">
              Sending Domains
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200">
              DKIM & SPF Engine
            </span>
          </div>
          <p className="text-sm text-slate-500 mt-1">
            Authenticate your custom domains with 2048-bit DKIM cryptographic keys, SPF, and DMARC for 99.9% inbox placement.
          </p>
        </div>

        <button
          onClick={() => setAddingDomain(true)}
          className="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-semibold text-white bg-indigo-600 rounded-lg hover:bg-indigo-700 transition-colors shadow-sm"
        >
          <Plus className="w-4 h-4" />
          Add Domain
        </button>
      </div>

      {/* Add Domain Modal / Drawer */}
      {addingDomain && (
        <div className="bg-white border-2 border-indigo-500/20 rounded-xl p-6 shadow-md transition-all">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Globe className="w-5 h-5 text-indigo-600" />
              <h2 className="text-lg font-semibold text-slate-900">Connect a Sending Domain</h2>
            </div>
            <button
              onClick={() => {
                setAddingDomain(false);
                setAddError("");
              }}
              className="text-slate-400 hover:text-slate-600 text-sm font-medium"
            >
              Cancel
            </button>
          </div>

          <form onSubmit={handleAddDomain} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-700 mb-1.5">
                Domain Name
              </label>
              <div className="relative">
                <input
                  type="text"
                  placeholder="e.g. acme.com or mail.acme.com"
                  value={newDomainInput}
                  onChange={(e) => setNewDomainInput(e.target.value)}
                  className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-300 rounded-lg text-sm text-slate-900 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 font-mono"
                  disabled={submitting}
                  autoFocus
                />
              </div>
              <p className="text-xs text-slate-500 mt-1">
                MailForge will generate an RSA-2048 DKIM keypair and custom DNS records for this domain.
              </p>
            </div>

            {addError && (
              <div className="flex items-center gap-2 p-3 text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-lg">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{addError}</span>
              </div>
            )}

            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setAddingDomain(false)}
                className="px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 rounded-lg"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting || !newDomainInput.trim()}
                className="inline-flex items-center gap-2 px-5 py-2 text-sm font-semibold text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg disabled:opacity-50"
              >
                {submitting ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Generating DKIM Keys...
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
        <div className="flex items-center justify-center p-12 bg-white rounded-xl border border-slate-200">
          <div className="flex items-center gap-3 text-slate-500 text-sm">
            <RefreshCw className="w-5 h-5 animate-spin text-indigo-600" />
            Loading domain configurations...
          </div>
        </div>
      ) : domains.length === 0 ? (
        <div className="text-center p-12 bg-white rounded-xl border border-dashed border-slate-300">
          <Globe className="w-12 h-12 text-slate-400 mx-auto mb-3" />
          <h3 className="text-base font-semibold text-slate-900">No Custom Domains Connected</h3>
          <p className="text-sm text-slate-500 max-w-md mx-auto mt-1 mb-6">
            Add your domain to generate 2048-bit DKIM keys and SPF verification records. Send transactional and bulk emails under your own brand identity without Resend.
          </p>
          <button
            onClick={() => setAddingDomain(true)}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold text-white bg-indigo-600 rounded-lg hover:bg-indigo-700"
          >
            <Plus className="w-4 h-4" />
            Add Your First Domain
          </button>
        </div>
      ) : (
        <div className="space-y-6">
          {domains.map((domain) => {
            const isExpanded = expandedDomain === domain.id;
            const isVerified = domain.status === "verified";
            const isVerifying = verifyingId === domain.id;

            return (
              <div
                key={domain.id}
                className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden transition-all"
              >
                {/* Domain Header Row */}
                <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-50/50">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-600 shrink-0">
                      <Globe className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-base font-bold text-slate-900 font-mono">
                          {domain.domain}
                        </span>
                        {isVerified ? (
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            Verified
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">
                            <Clock className="w-3.5 h-3.5" />
                            Pending DNS
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-slate-500 mt-0.5">
                        Selector: <code className="font-mono text-indigo-700 font-medium">{domain.selector || "mf1"}</code> • Added on {new Date(domain.createdAt).toLocaleDateString()}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleVerifyDns(domain)}
                      disabled={isVerifying}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-700 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 transition-colors disabled:opacity-50 shadow-xs"
                      title="Run live DNS query against 8.8.8.8 / 1.1.1.1"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${isVerifying ? "animate-spin text-indigo-600" : ""}`} />
                      {isVerifying ? "Checking DNS..." : "Verify DNS"}
                    </button>

                    <button
                      onClick={() => handleDeleteDomain(domain)}
                      className="p-1.5 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors"
                      title="Delete domain"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>

                    <button
                      onClick={() => setExpandedDomain(isExpanded ? null : domain.id)}
                      className="p-1.5 text-slate-500 hover:text-slate-700 hover:bg-slate-100 rounded-lg transition-colors"
                      title={isExpanded ? "Collapse records" : "View DNS records"}
                    >
                      {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                    </button>
                  </div>
                </div>

                {/* Collapsible DNS Records Table */}
                {isExpanded && (
                  <div className="p-6 border-t border-slate-200 space-y-6">
                    <div>
                      <h4 className="text-sm font-semibold text-slate-900 mb-1">
                        Required DNS Configuration Records
                      </h4>
                      <p className="text-xs text-slate-500">
                        Add these records to your DNS manager (e.g. Cloudflare, GoDaddy, Namecheap, Route 53). Once added, click <strong>Verify DNS</strong>.
                      </p>
                    </div>

                    <div className="overflow-x-auto border border-slate-200 rounded-lg">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-slate-100/75 text-slate-700 font-semibold border-b border-slate-200">
                          <tr>
                            <th className="py-2.5 px-3">Type</th>
                            <th className="py-2.5 px-3">Host / Name</th>
                            <th className="py-2.5 px-3">Value / Content</th>
                            <th className="py-2.5 px-3">Purpose</th>
                            <th className="py-2.5 px-3 text-right">Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-200 font-mono">
                          {domain.records?.map((record, idx) => {
                            const nameKey = `${domain.id}-name-${idx}`;
                            const valKey = `${domain.id}-val-${idx}`;

                            return (
                              <tr key={idx} className="hover:bg-slate-50/70 transition-colors">
                                <td className="py-3 px-3 font-bold text-indigo-700">
                                  {record.type}
                                </td>
                                <td className="py-3 px-3 max-w-[200px]">
                                  <div className="flex items-center gap-1.5">
                                    <span className="truncate select-all text-slate-800" title={record.name}>
                                      {record.name}
                                    </span>
                                    <button
                                      onClick={() => copyToClipboard(record.name, nameKey)}
                                      className="text-slate-400 hover:text-slate-600 shrink-0"
                                      title="Copy Host"
                                    >
                                      {copiedKey === nameKey ? (
                                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                                      ) : (
                                        <Copy className="w-3.5 h-3.5" />
                                      )}
                                    </button>
                                  </div>
                                </td>
                                <td className="py-3 px-3 max-w-[340px]">
                                  <div className="flex items-center gap-1.5">
                                    <span
                                      className="truncate select-all text-slate-600 text-[11px]"
                                      title={record.value}
                                    >
                                      {record.value}
                                    </span>
                                    <button
                                      onClick={() => copyToClipboard(record.value, valKey)}
                                      className="text-slate-400 hover:text-slate-600 shrink-0"
                                      title="Copy Value"
                                    >
                                      {copiedKey === valKey ? (
                                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                                      ) : (
                                        <Copy className="w-3.5 h-3.5" />
                                      )}
                                    </button>
                                  </div>
                                </td>
                                <td className="py-3 px-3 font-sans">
                                  <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-100 text-slate-700">
                                    {record.purpose}
                                  </span>
                                </td>
                                <td className="py-3 px-3 text-right font-sans">
                                  {record.status === "verified" ? (
                                    <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-700">
                                      <CheckCircle2 className="w-3 h-3" />
                                      Active
                                    </span>
                                  ) : (
                                    <span className="inline-flex items-center gap-1 text-[11px] font-medium text-amber-600">
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

                    <div className="p-3.5 bg-blue-50/70 border border-blue-200/60 rounded-lg flex items-start gap-2.5 text-xs text-blue-900">
                      <Info className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                      <div>
                        <strong>DNS Propagation Notice:</strong> DNS records typically take between 2 to 30 minutes to propagate worldwide. If records show pending, wait a few minutes and click &quot;Verify DNS&quot;.
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Feature Explainer Banner */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-4">
        <div className="bg-white p-5 rounded-xl border border-slate-200">
          <div className="w-8 h-8 rounded-lg bg-emerald-50 text-emerald-600 flex items-center justify-center mb-3">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <h4 className="text-sm font-bold text-slate-900 mb-1">DKIM Cryptographic Signing</h4>
          <p className="text-xs text-slate-500 leading-relaxed">
            MailForge generates an RSA-2048 private key kept safely in encrypted storage. Outgoing emails are signed with standard RFC 6376 headers to prevent spoofing.
          </p>
        </div>

        <div className="bg-white p-5 rounded-xl border border-slate-200">
          <div className="w-8 h-8 rounded-lg bg-indigo-50 text-indigo-600 flex items-center justify-center mb-3">
            <Server className="w-4 h-4" />
          </div>
          <h4 className="text-sm font-bold text-slate-900 mb-1">Direct DNS Verification</h4>
          <p className="text-xs text-slate-500 leading-relaxed">
            No middleman services needed. MailForge directly queries root resolvers (8.8.8.8 and 1.1.1.1) to audit SPF, DMARC, and DKIM public records in real-time.
          </p>
        </div>

        <div className="bg-white p-5 rounded-xl border border-slate-200">
          <div className="w-8 h-8 rounded-lg bg-purple-50 text-purple-600 flex items-center justify-center mb-3">
            <Globe className="w-4 h-4" />
          </div>
          <h4 className="text-sm font-bold text-slate-900 mb-1">Self-Hosted Freedom</h4>
          <p className="text-xs text-slate-500 leading-relaxed">
            You own your email delivery infrastructure. Send from any verified domain via Gmail App Password, custom SMTP servers, or developer REST APIs.
          </p>
        </div>
      </div>
    </div>
  );
}
