"use client";

import React, { useState, useEffect } from "react";
import { apiFetch } from "@/lib/api-client";
import {
  Key,
  Plus,
  Trash2,
  Copy,
  Check,
  RefreshCw,
  AlertTriangle,
  Code2,
  Terminal,
  ShieldCheck,
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
      if (res.keys) setKeys(res.keys);
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
        body: JSON.stringify({ name: keyName.trim() }),
      });

      if (res.success && res.key) {
        setNewlyCreatedKey(res.key.key);
        setKeys((prev) => [
          {
            id: res.key.id,
            name: res.key.name,
            keyPrefix: res.key.keyPrefix,
            createdAt: res.key.createdAt,
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
      await apiFetch(`/api/v1/api-keys/${encodeURIComponent(key.id)}`, {
        method: "DELETE",
      });
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
    <div className="max-w-6xl mx-auto space-y-8 pb-16">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-200 pb-6">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-slate-900">
              Developer API Keys
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
              REST Email API
            </span>
          </div>
          <p className="text-sm text-slate-500 mt-1">
            Programmatically dispatch transactional emails via our native REST API (<code className="font-mono text-indigo-600 font-medium">/api/v1/emails</code>) just like Resend.
          </p>
        </div>

        <button
          onClick={() => setCreating(true)}
          className="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-semibold text-white bg-indigo-600 rounded-lg hover:bg-indigo-700 transition-colors shadow-sm"
        >
          <Plus className="w-4 h-4" />
          Create API Key
        </button>
      </div>

      {/* Secret Key Revealed Banner (One-Time Display) */}
      {newlyCreatedKey && (
        <div className="bg-emerald-50 border-2 border-emerald-500/30 rounded-xl p-6 shadow-sm space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-emerald-900 font-semibold text-sm">
              <Sparkles className="w-4 h-4 text-emerald-600" />
              API Key Created Successfully
            </div>
            <button
              onClick={() => setNewlyCreatedKey(null)}
              className="text-xs text-emerald-700 hover:text-emerald-900 font-medium"
            >
              Done & Close
            </button>
          </div>

          <p className="text-xs text-emerald-800">
            Please copy this API key immediately. For your security, it will <strong>never be shown again</strong>.
          </p>

          <div className="flex items-center gap-2 bg-white border border-emerald-200 p-2.5 rounded-lg">
            <code className="text-xs font-mono font-bold text-slate-900 flex-1 select-all break-all">
              {newlyCreatedKey}
            </code>
            <button
              onClick={() => copyToClipboard(newlyCreatedKey, "created-key")}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-700 rounded-md shrink-0 transition-colors"
            >
              {copiedKey === "created-key" ? (
                <>
                  <Check className="w-3.5 h-3.5" />
                  Copied
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  Copy Secret
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {/* Create Key Modal */}
      {creating && (
        <div className="bg-white border-2 border-indigo-500/20 rounded-xl p-6 shadow-md">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Key className="w-5 h-5 text-indigo-600" />
              <h2 className="text-lg font-semibold text-slate-900">Create New API Key</h2>
            </div>
            <button
              onClick={() => setCreating(false)}
              className="text-slate-400 hover:text-slate-600 text-sm font-medium"
            >
              Cancel
            </button>
          </div>

          <form onSubmit={handleCreateKey} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-700 mb-1.5">
                Key Name
              </label>
              <input
                type="text"
                placeholder="e.g. Production Backend, Next.js Server, Zapier"
                value={keyName}
                onChange={(e) => setKeyName(e.target.value)}
                className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-300 rounded-lg text-sm text-slate-900 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                disabled={submitting}
                autoFocus
              />
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setCreating(false)}
                className="px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 rounded-lg"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting || !keyName.trim()}
                className="inline-flex items-center gap-2 px-5 py-2 text-sm font-semibold text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg disabled:opacity-50"
              >
                {submitting ? "Generating..." : "Generate Key"}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Keys List */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
        <div className="p-5 border-b border-slate-200">
          <h3 className="text-base font-bold text-slate-900">Active API Keys</h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Keys are securely hashed with SHA-256 in MongoDB. Only you have access to the raw key secret.
          </p>
        </div>

        {loading ? (
          <div className="p-8 text-center text-slate-500 text-sm flex items-center justify-center gap-2">
            <RefreshCw className="w-4 h-4 animate-spin text-indigo-600" />
            Loading API keys...
          </div>
        ) : keys.length === 0 ? (
          <div className="p-10 text-center">
            <Key className="w-10 h-10 text-slate-300 mx-auto mb-2" />
            <p className="text-sm font-medium text-slate-700">No developer API keys yet</p>
            <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1 mb-4">
              Create an API key to dispatch transactional emails from your server or backend application.
            </p>
            <button
              onClick={() => setCreating(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-indigo-600 rounded-lg hover:bg-indigo-700"
            >
              <Plus className="w-3.5 h-3.5" />
              Create Key
            </button>
          </div>
        ) : (
          <div className="divide-y divide-slate-200">
            {keys.map((k) => (
              <div
                key={k.id}
                className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-slate-50/50 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg bg-slate-100 flex items-center justify-center text-slate-600 shrink-0">
                    <Key className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-slate-900">{k.name}</h4>
                    <p className="text-xs font-mono text-slate-500 mt-0.5">
                      {k.keyPrefix}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-6 text-xs text-slate-500">
                  <div className="flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5 text-slate-400" />
                    <span>Created: {new Date(k.createdAt).toLocaleDateString()}</span>
                  </div>

                  <div>
                    {k.lastUsedAt ? (
                      <span className="text-emerald-700 font-medium">
                        Last used: {new Date(k.lastUsedAt).toLocaleDateString()}
                      </span>
                    ) : (
                      <span className="text-slate-400 italic">Never used</span>
                    )}
                  </div>

                  <button
                    onClick={() => handleRevokeKey(k)}
                    className="p-1.5 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors"
                    title="Revoke API key"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Interactive Code Snippets / Quickstart */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
        <div className="p-5 border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-50/50">
          <div>
            <div className="flex items-center gap-2">
              <Code2 className="w-5 h-5 text-indigo-600" />
              <h3 className="text-base font-bold text-slate-900">Developer Integration Quickstart</h3>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              Send your first email with MailForge using your preferred language or HTTP tool.
            </p>
          </div>

          <div className="flex items-center gap-1 bg-slate-200/70 p-1 rounded-lg">
            <button
              onClick={() => setActiveTab("curl")}
              className={`px-3 py-1 rounded-md text-xs font-semibold transition-colors ${
                activeTab === "curl"
                  ? "bg-white text-slate-900 shadow-xs"
                  : "text-slate-600 hover:text-slate-900"
              }`}
            >
              cURL
            </button>
            <button
              onClick={() => setActiveTab("ts")}
              className={`px-3 py-1 rounded-md text-xs font-semibold transition-colors ${
                activeTab === "ts"
                  ? "bg-white text-slate-900 shadow-xs"
                  : "text-slate-600 hover:text-slate-900"
              }`}
            >
              TypeScript / JS
            </button>
            <button
              onClick={() => setActiveTab("python")}
              className={`px-3 py-1 rounded-md text-xs font-semibold transition-colors ${
                activeTab === "python"
                  ? "bg-white text-slate-900 shadow-xs"
                  : "text-slate-600 hover:text-slate-900"
              }`}
            >
              Python
            </button>
          </div>
        </div>

        <div className="p-5 bg-slate-950 font-mono text-xs text-slate-200 overflow-x-auto relative">
          <button
            onClick={() => {
              const snippet =
                activeTab === "curl"
                  ? `curl -X POST https://your-mailforge-app.com/api/v1/emails \\\n  -H "Authorization: Bearer mf_live_YOUR_API_KEY" \\\n  -H "Content-Type: application/json" \\\n  -d '{\n    "from": "Acme <hello@yourdomain.com>",\n    "to": "customer@example.com",\n    "subject": "Order Confirmation",\n    "html": "<strong>Thank you for your order!</strong>"\n  }'`
                  : activeTab === "ts"
                  ? `const response = await fetch("https://your-mailforge-app.com/api/v1/emails", {\n  method: "POST",\n  headers: {\n    "Authorization": "Bearer mf_live_YOUR_API_KEY",\n    "Content-Type": "application/json",\n  },\n  body: JSON.stringify({\n    from: "Acme <hello@yourdomain.com>",\n    to: "customer@example.com",\n    subject: "Order Confirmation",\n    html: "<strong>Thank you for your order!</strong>",\n  }),\n});\n\nconst data = await response.json();\nconsole.log("Email dispatched:", data.id);`
                  : `import requests\n\nresponse = requests.post(\n    "https://your-mailforge-app.com/api/v1/emails",\n    headers={\n        "Authorization": "Bearer mf_live_YOUR_API_KEY",\n        "Content-Type": "application/json",\n    },\n    json={\n        "from": "Acme <hello@yourdomain.com>",\n        "to": "customer@example.com",\n        "subject": "Order Confirmation",\n        "html": "<strong>Thank you for your order!</strong>",\n    }\n)\n\nprint(response.json())`;
              copyToClipboard(snippet, "snippet");
            }}
            className="absolute top-4 right-4 inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-sans font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded transition-colors"
          >
            {copiedKey === "snippet" ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                Copied
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                Copy Snippet
              </>
            )}
          </button>

          {activeTab === "curl" && (
            <pre className="text-slate-300 leading-relaxed">
              {`curl -X POST https://your-mailforge-app.com/api/v1/emails \\
  -H "Authorization: Bearer mf_live_YOUR_API_KEY" \\
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
            <pre className="text-emerald-300 leading-relaxed">
              {`const response = await fetch("https://your-mailforge-app.com/api/v1/emails", {
  method: "POST",
  headers: {
    "Authorization": "Bearer mf_live_YOUR_API_KEY",
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
            <pre className="text-sky-300 leading-relaxed">
              {`import requests

response = requests.post(
    "https://your-mailforge-app.com/api/v1/emails",
    headers={
        "Authorization": "Bearer mf_live_YOUR_API_KEY",
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
