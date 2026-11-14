"use client";

import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import { apiFetch } from "@/lib/api-client";
import {
  Key,
  Plus,
  Trash2,
  Copy,
  Check,
  RefreshCw,
  Code2,
  Clock,
  Sparkles,
} from "lucide-react";

interface ApiKeyItem {
  id: string;
  name: string;
  keyPrefix: string;
  createdAt: string;
  lastUsedAt: string | null;
}

export default function ApiKeysPage() {
  const [keys, setKeys] = useState<ApiKeyItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [newlyCreatedKey, setNewlyCreatedKey] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"curl" | "ts" | "python">("curl");

  const fetchKeys = async () => {
    try {
      setLoading(true);
      const res = await apiFetch("/api/v1/api-keys");
      const data = await res.json().catch(() => ({}));
      if (res.ok && Array.isArray(data.keys)) setKeys(data.keys);
    } catch (err) {
      console.error("Failed to load API keys:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchKeys();
  }, []);

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyName.trim()) return;

    try {
      setSubmitting(true);
      const res = await apiFetch("/api/v1/api-keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: keyName.trim() }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.error || "Failed to create API key.");
      }

      if (data.key) {
        setNewlyCreatedKey(data.key.key);
        setKeys((prev) => [
          {
            id: data.key.id,
            name: data.key.name,
            keyPrefix: data.key.keyPrefix,
            createdAt: data.key.createdAt,
            lastUsedAt: null,
          },
          ...prev,
        ]);
        setKeyName("");
        setCreating(false);
      }
    } catch (err: any) {
      alert(`Error creating key: ${err?.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleRevokeKey = async (key: ApiKeyItem) => {
    if (!window.confirm(`Revoke API Key "${key.name}"? Applications using this key will immediately fail.`)) return;

    try {
      const res = await apiFetch(`/api/v1/api-keys/${encodeURIComponent(key.id)}`, {
        method: "DELETE",
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || "Failed to revoke key.");
      }
      setKeys((prev) => prev.filter((k) => k.id !== key.id));
    } catch (err: any) {
      alert(`Failed to revoke key: ${err?.message}`);
    }
  };

  const copyToClipboard = (text: string, identifier: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(identifier);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="space-y-6 pb-16">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#262A2E] pb-6">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-medium tracking-tight text-white">
              Developer API Keys
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#171A1D] text-zinc-300 border border-[#262A2E]">
              REST EMAIL API
            </span>
          </div>
          <p className="text-xs text-zinc-400 font-mono mt-1">
            Programmatically dispatch transactional emails via our native REST endpoint (<code className="text-zinc-200">/api/v1/emails</code>).
          </p>
        </div>

        <motion.button
          whileHover={{ y: -1 }}
          whileTap={{ scale: 0.98 }}
          onClick={() => setCreating(true)}
          className="inline-flex items-center justify-center gap-2 px-4 py-1.5 text-xs font-medium text-black bg-white rounded-lg hover:bg-zinc-200 transition-colors shadow-sm"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Create API Key</span>
        </motion.button>
      </div>

      {/* Secret Key Revealed Banner (One-Time Display) */}
      <AnimatePresence>
        {newlyCreatedKey && (
          <motion.div
            initial={{ opacity: 0, scale: 0.98, y: -6 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.98, y: -6 }}
            className="bg-[#111315] border border-emerald-500/30 rounded-xl p-5 space-y-3 font-mono"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-emerald-400 font-medium text-xs">
                <Sparkles className="w-4 h-4 text-emerald-400" />
                API Key Generated Successfully
              </div>
              <button
                onClick={() => setNewlyCreatedKey(null)}
                className="text-xs text-zinc-400 hover:text-white"
              >
                Done & Dismiss
              </button>
            </div>

            <p className="text-xs text-zinc-400">
              Copy this secret key now. For your security, it will <strong>never be shown again</strong>.
            </p>

            <div className="flex items-center gap-2 bg-[#171A1D] border border-[#262A2E] p-2.5 rounded-lg">
              <code className="text-xs text-white flex-1 select-all break-all">
                {newlyCreatedKey}
              </code>
              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => copyToClipboard(newlyCreatedKey, "created-key")}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-black bg-white hover:bg-zinc-200 rounded-md shrink-0 transition-colors"
              >
                {copiedKey === "created-key" ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-black" />
                    Copied
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    Copy Secret
                  </>
                )}
              </motion.button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Create Key Drawer */}
      <AnimatePresence>
        {creating && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="bg-[#111315] border border-[#262A2E] rounded-xl p-5 space-y-4 overflow-hidden"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Key className="w-4 h-4 text-zinc-400" />
                <h2 className="text-sm font-medium text-white">Create New API Key</h2>
              </div>
              <button
                onClick={() => setCreating(false)}
                className="text-zinc-500 hover:text-white text-xs font-mono"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleCreateKey} className="space-y-4">
              <div>
                <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                  Key Identifier
                </label>
                <input
                  type="text"
                  placeholder="e.g. Production Backend, Next.js Server"
                  value={keyName}
                  onChange={(e) => setKeyName(e.target.value)}
                  className="w-full px-3 py-2 bg-[#171A1D] border border-[#262A2E] rounded-lg text-xs text-white font-mono focus:border-zinc-500 focus:outline-none"
                  disabled={submitting}
                  autoFocus
                />
              </div>

              <div className="flex justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => setCreating(false)}
                  className="px-3.5 py-1.5 text-xs font-mono text-zinc-400 hover:text-white rounded-lg"
                >
                  Cancel
                </button>
                <motion.button
                  whileHover={{ y: -1 }}
                  whileTap={{ scale: 0.98 }}
                  type="submit"
                  disabled={submitting || !keyName.trim()}
                  className="inline-flex items-center gap-2 px-4 py-1.5 text-xs font-medium text-black bg-white hover:bg-zinc-200 rounded-lg disabled:opacity-50 transition-colors"
                >
                  {submitting ? "Generating..." : "Generate Key"}
                </motion.button>
              </div>
            </form>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Keys List */}
      <div className="bg-[#111315] rounded-xl border border-[#262A2E] overflow-hidden">
        <div className="p-4 border-b border-[#262A2E]">
          <h3 className="text-sm font-medium text-white">Active API Keys</h3>
          <p className="text-xs text-zinc-400 font-mono mt-0.5">
            Keys are securely hashed with SHA-256. Raw secrets are only revealed upon creation.
          </p>
        </div>

        {loading ? (
          <div className="p-8 text-center text-zinc-500 font-mono text-xs flex items-center justify-center gap-2">
            <RefreshCw className="w-4 h-4 animate-spin text-white" />
            LOADING API KEYS...
          </div>
        ) : keys.length === 0 ? (
          <div className="p-10 text-center">
            <Key className="w-8 h-8 text-zinc-600 mx-auto mb-2" />
            <p className="text-sm font-medium text-white">No active API keys</p>
            <p className="text-xs text-zinc-500 font-mono max-w-sm mx-auto mt-1 mb-4">
              Create an API key to dispatch transactional emails from your server application.
            </p>
            <button
              onClick={() => setCreating(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-black bg-white rounded-lg hover:bg-zinc-200 transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Create Key</span>
            </button>
          </div>
        ) : (
          <div className="divide-y divide-[#1C2024]">
            {keys.map((k) => (
              <div
                key={k.id}
                className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-[#171A1D]/40 transition-colors font-mono"
              >
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-[#171A1D] border border-[#262A2E] flex items-center justify-center text-zinc-400 shrink-0">
                    <Key className="w-3.5 h-3.5" />
                  </div>
                  <div>
                    <h4 className="text-xs font-medium text-white font-sans">{k.name}</h4>
                    <p className="text-[11px] text-zinc-400 mt-0.5">
                      {k.keyPrefix}••••••••••••
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-6 text-[11px] text-zinc-400">
                  <div className="flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5 text-zinc-500" />
                    <span>Created: {new Date(k.createdAt).toLocaleDateString()}</span>
                  </div>

                  <div>
                    {k.lastUsedAt ? (
                      <span className="text-emerald-400">
                        Last used: {new Date(k.lastUsedAt).toLocaleDateString()}
                      </span>
                    ) : (
                      <span className="text-zinc-600 italic">Never used</span>
                    )}
                  </div>

                  <button
                    onClick={() => handleRevokeKey(k)}
                    className="p-1.5 text-zinc-500 hover:text-red-400 hover:bg-[#171A1D] rounded-lg transition-colors"
                    title="Revoke API key"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Code Snippets / Quickstart */}
      <div className="bg-[#111315] rounded-xl border border-[#262A2E] overflow-hidden">
        <div className="p-4 border-b border-[#262A2E] flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#171A1D]/40">
          <div>
            <div className="flex items-center gap-2">
              <Code2 className="w-4 h-4 text-zinc-400" />
              <h3 className="text-sm font-medium text-white">Developer Integration Quickstart</h3>
            </div>
            <p className="text-xs text-zinc-400 font-mono mt-0.5">
              Send an email via HTTP REST dispatch.
            </p>
          </div>

          <div className="flex items-center gap-1 bg-[#111315] border border-[#262A2E] p-0.5 rounded-lg font-mono">
            <button
              onClick={() => setActiveTab("curl")}
              className={`px-3 py-1 rounded text-xs transition-colors ${
                activeTab === "curl"
                  ? "bg-[#171A1D] text-white font-medium"
                  : "text-zinc-500 hover:text-zinc-300"
              }`}
            >
              cURL
            </button>
            <button
              onClick={() => setActiveTab("ts")}
              className={`px-3 py-1 rounded text-xs transition-colors ${
                activeTab === "ts"
                  ? "bg-[#171A1D] text-white font-medium"
                  : "text-zinc-500 hover:text-zinc-300"
              }`}
            >
              TypeScript
            </button>
            <button
              onClick={() => setActiveTab("python")}
              className={`px-3 py-1 rounded text-xs transition-colors ${
                activeTab === "python"
                  ? "bg-[#171A1D] text-white font-medium"
                  : "text-zinc-500 hover:text-zinc-300"
              }`}
            >
              Python
            </button>
          </div>
        </div>

        <div className="p-5 bg-[#08090A] font-mono text-xs text-zinc-300 overflow-x-auto relative">
          <button
            onClick={() => {
              const snippet =
                activeTab === "curl"
                  ? `curl -X POST https://postvane.netlify.app/api/v1/emails \\\n  -H "Authorization: Bearer pv_live_YOUR_API_KEY" \\\n  -H "Content-Type: application/json" \\\n  -d '{\n    "from": "Acme <hello@yourdomain.com>",\n    "to": "customer@example.com",\n    "subject": "Order Confirmation",\n    "html": "<strong>Thank you for your order!</strong>"\n  }'`
                  : activeTab === "ts"
                  ? `const response = await fetch("https://postvane.netlify.app/api/v1/emails", {\n  method: "POST",\n  headers: {\n    "Authorization": "Bearer pv_live_YOUR_API_KEY",\n    "Content-Type": "application/json",\n  },\n  body: JSON.stringify({\n    from: "Acme <hello@yourdomain.com>",\n    to: "customer@example.com",\n    subject: "Order Confirmation",\n    html: "<strong>Thank you for your order!</strong>",\n  }),\n});\n\nconst data = await response.json();\nconsole.log("Email dispatched:", data.id);`
                  : `import requests\n\nresponse = requests.post(\n    "https://postvane.netlify.app/api/v1/emails",\n    headers={\n        "Authorization": "Bearer pv_live_YOUR_API_KEY",\n        "Content-Type": "application/json",\n    },\n    json={\n        "from": "Acme <hello@yourdomain.com>",\n        "to": "customer@example.com",\n        "subject": "Order Confirmation",\n        "html": "<strong>Thank you for your order!</strong>",\n    }\n)\n\nprint(response.json())`;
              copyToClipboard(snippet, "snippet");
            }}
            className="absolute top-4 right-4 inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono text-zinc-300 bg-[#171A1D] border border-[#262A2E] hover:border-zinc-500 rounded transition-colors"
          >
            {copiedKey === "snippet" ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                Copied
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                Copy
              </>
            )}
          </button>

          {activeTab === "curl" && (
            <pre className="text-zinc-300 leading-relaxed">
              {`curl -X POST https://postvane.netlify.app/api/v1/emails \\
  -H "Authorization: Bearer pv_live_YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "from": "Acme <hello@yourdomain.com>",
    "to": "customer@example.com",
    "subject": "Order Confirmation",
    "html": "<strong>Thank you for your order!</strong>"
  }'`}
            </pre>
          )}

          {activeTab === "ts" && (
            <pre className="text-zinc-300 leading-relaxed">
              {`const response = await fetch("https://postvane.netlify.app/api/v1/emails", {
  method: "POST",
  headers: {
    "Authorization": "Bearer pv_live_YOUR_API_KEY",
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    from: "Acme <hello@yourdomain.com>",
    to: "customer@example.com",
    subject: "Order Confirmation",
    html: "<strong>Thank you for your order!</strong>",
  }),
});

const data = await response.json();
console.log("Email dispatched:", data.id);`}
            </pre>
          )}

          {activeTab === "python" && (
            <pre className="text-zinc-300 leading-relaxed">
              {`import requests

response = requests.post(
    "https://postvane.netlify.app/api/v1/emails",
    headers={
        "Authorization": "Bearer pv_live_YOUR_API_KEY",
        "Content-Type": "application/json",
    },
    json={
        "from": "Acme <hello@yourdomain.com>",
        "to": "customer@example.com",
        "subject": "Order Confirmation",
        "html": "<strong>Thank you for your order!</strong>",
    }
)

print(response.json())`}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}
