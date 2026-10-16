"use client";

import React, { useState, useEffect } from "react";
import { useAuth } from "@/context/auth-context";
import { updateUserSettings } from "@/lib/store/db-service";
import { UserSettings, SmtpConfig, GmailConfig } from "@/types";
import {
  Settings,
  ShieldCheck,
  User,
  Mail,
  Clock,
  Save,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
  Server,
  Zap,
  Activity,
  Check,
  Eye,
  EyeOff,
  Send,
  HelpCircle,
  KeyRound,
  Sparkles,
  Info,
} from "lucide-react";

export default function SettingsPage() {
  const { user, profile, refreshProfile } = useAuth();
  const userId = user?.uid || profile?.uid || "";

  // General Sender Identity
  const [fromName, setFromName] = useState("");
  const [fromEmail, setFromEmail] = useState("");
  const [replyTo, setReplyTo] = useState("");
  const [timezone, setTimezone] = useState("UTC");
  const [trackOpens, setTrackOpens] = useState(true);
  const [trackClicks, setTrackClicks] = useState(true);
  const [autoAppendUnsubscribe, setAutoAppendUnsubscribe] = useState(true);

  // Delivery Method Selection ("gmail_app_password" | "custom_smtp")
  const [deliveryMethod, setDeliveryMethod] = useState<"gmail_app_password" | "custom_smtp">("gmail_app_password");

  // Gmail App Password Configuration
  const [gmailEmail, setGmailEmail] = useState("");
  const [gmailAppPassword, setGmailAppPassword] = useState("");
  const [showGmailPassword, setShowGmailPassword] = useState(false);
  const [showHelpGuide, setShowHelpGuide] = useState(false);

  // Custom SMTP Configuration
  const [smtpHost, setSmtpHost] = useState("");
  const [smtpPort, setSmtpPort] = useState(587);
  const [smtpUser, setSmtpUser] = useState("");
  const [smtpPass, setSmtpPass] = useState("");
  const [smtpSecure, setSmtpSecure] = useState(false);
  const [showSmtpPassword, setShowSmtpPassword] = useState(false);

  // Test Connection & Sending State
  const [testingConnection, setTestingConnection] = useState(false);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    message: string;
  } | null>(null);

  const [sendingTestEmail, setSendingTestEmail] = useState(false);
  const [testEmailResult, setTestEmailResult] = useState<{
    success: boolean;
    message: string;
  } | null>(null);

  const [saving, setSaving] = useState(false);
  const [statusMessage, setStatusMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  useEffect(() => {
    if (profile?.settings) {
      setFromName(profile.settings.defaultFromName || profile.displayName || user?.displayName || "MailForge Sender");
      setReplyTo(profile.settings.defaultReplyTo || "");
      setTimezone(profile.settings.timezone || "UTC");
      setTrackOpens(profile.settings.trackOpens !== false);
      setTrackClicks(profile.settings.trackClicks !== false);
      setAutoAppendUnsubscribe(profile.settings.autoAppendUnsubscribe !== false);

      const method = profile.settings.deliveryMethod === "custom_smtp" ? "custom_smtp" : "gmail_app_password";
      setDeliveryMethod(method);

      // Load Gmail settings
      const gEmail = profile.settings.gmail?.email || (profile.email?.endsWith("@gmail.com") ? profile.email : user?.email || "");
      setGmailEmail(gEmail);
      setGmailAppPassword(profile.settings.gmail?.appPassword || "");

      // Load From Email
      setFromEmail(profile.settings.defaultFromEmail || gEmail);

      // Load SMTP settings
      if (profile.settings.smtp) {
        setSmtpHost(profile.settings.smtp.host || "");
        setSmtpPort(profile.settings.smtp.port || 587);
        setSmtpUser(profile.settings.smtp.user || "");
        setSmtpPass(profile.settings.smtp.pass || "");
        setSmtpSecure(Boolean(profile.settings.smtp.secure));
      }
    } else {
      // Default initial states
      const defaultMail = user?.email || "";
      setGmailEmail(defaultMail);
      setFromEmail(defaultMail);
      setFromName(user?.displayName || "MailForge Dispatcher");
    }
  }, [profile, user]);

  // Apply quick presets for custom SMTP
  const applyPreset = (preset: "brevo" | "postmark" | "custom") => {
    if (preset === "brevo") {
      setSmtpHost("smtp-relay.brevo.com");
      setSmtpPort(587);
      setSmtpSecure(false);
    } else if (preset === "postmark") {
      setSmtpHost("smtp.postmarkapp.com");
      setSmtpPort(587);
      setSmtpSecure(false);
    } else {
      setSmtpHost("");
      setSmtpPort(587);
      setSmtpSecure(false);
    }
  };

  // Test credentials connection
  const handleTestConnection = async () => {
    setTestingConnection(true);
    setTestResult(null);

    const isGmailMode = deliveryMethod === "gmail_app_password";
    const host = isGmailMode ? "smtp.gmail.com" : smtpHost.trim();
    const port = isGmailMode ? 465 : Number(smtpPort) || 587;
    const userToTest = isGmailMode ? gmailEmail.trim() : smtpUser.trim();
    const passToTest = isGmailMode ? gmailAppPassword.trim().replace(/\s+/g, "") : smtpPass.trim();
    const secure = isGmailMode ? true : smtpSecure || port === 465;

    try {
      const res = await fetch("/api/smtp/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          host,
          port,
          user: userToTest,
          pass: passToTest,
          secure,
          isGmail: isGmailMode,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to verify credentials");
      }

      setTestResult({
        success: true,
        message: data.message || "Connection established successfully!",
      });
    } catch (err: any) {
      setTestResult({
        success: false,
        message: err.message || "Connection failed. Please verify credentials.",
      });
    } finally {
      setTestingConnection(false);
    }
  };

  // Send a test email directly through the active connection
  const handleSendTestMessage = async () => {
    setSendingTestEmail(true);
    setTestEmailResult(null);

    const isGmailMode = deliveryMethod === "gmail_app_password";
    const userEmail = isGmailMode ? gmailEmail.trim() : smtpUser.trim();
    const pass = isGmailMode ? gmailAppPassword.trim().replace(/\s+/g, "") : smtpPass.trim();

    const activeSmtpConfig: SmtpConfig = {
      host: isGmailMode ? "smtp.gmail.com" : smtpHost.trim(),
      port: isGmailMode ? 465 : Number(smtpPort) || 587,
      secure: isGmailMode ? true : smtpSecure || Number(smtpPort) === 465,
      user: userEmail,
      pass,
    };

    try {
      const target = user?.email || profile?.email || userEmail;
      const res = await fetch("/api/send-test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          to: target,
          subject: "Test Dispatch from MailForge",
          htmlContent: `
            <div style="font-family: sans-serif; padding: 24px; border: 1px solid #e2e8f0; border-radius: 8px;">
              <h2 style="color: #2563eb; margin-top: 0;">🎉 MailForge Delivery Verified!</h2>
              <p>Your <strong>${isGmailMode ? "Gmail Google App Password" : "Custom SMTP"}</strong> configuration is functioning correctly.</p>
              <p style="color: #64748b; font-size: 13px;">Sender: ${fromName} &lt;${fromEmail || userEmail}&gt;</p>
              <p style="color: #64748b; font-size: 12px; margin-top: 24px;">Sent via MailForge Production Engine.</p>
            </div>
          `,
          fromName: fromName || "MailForge Dispatcher",
          fromEmail: fromEmail || userEmail,
          smtpConfig: activeSmtpConfig,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to dispatch test email");
      }

      setTestEmailResult({
        success: true,
        message: `Test email successfully delivered to ${data.sentTo}!`,
      });
    } catch (err: any) {
      setTestEmailResult({
        success: false,
        message: err.message || "Failed to send test email.",
      });
    } finally {
      setSendingTestEmail(false);
    }
  };

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setStatusMessage(null);

    try {
      const isGmail = deliveryMethod === "gmail_app_password";
      const cleanGmailPass = gmailAppPassword.trim().replace(/\s+/g, "");

      const gmailConfig: GmailConfig = {
        email: gmailEmail.trim(),
        appPassword: cleanGmailPass,
        isConnected: Boolean(gmailEmail && cleanGmailPass),
      };

      const smtpConfig: SmtpConfig = isGmail
        ? {
            host: "smtp.gmail.com",
            port: 465,
            secure: true,
            user: gmailEmail.trim(),
            pass: cleanGmailPass,
          }
        : {
            host: smtpHost.trim(),
            port: Number(smtpPort) || 587,
            user: smtpUser.trim(),
            pass: smtpPass.trim().replace(/\s+/g, ""),
            secure: smtpSecure || Number(smtpPort) === 465,
          };

      const finalFromEmail = fromEmail.trim() || (isGmail ? gmailEmail.trim() : smtpUser.trim());

      const updated: Partial<UserSettings> = {
        defaultFromName: fromName.trim() || "MailForge Team",
        defaultFromEmail: finalFromEmail,
        defaultReplyTo: replyTo.trim(),
        timezone,
        trackOpens,
        trackClicks,
        autoAppendUnsubscribe,
        deliveryMethod,
        gmail: gmailConfig,
        smtp: smtpConfig,
      };

      await updateUserSettings(userId, updated);
      await refreshProfile();
      setStatusMessage({
        type: "success",
        text: "Configuration saved successfully! Your email sending credentials are active.",
      });
      setTimeout(() => setStatusMessage(null), 4000);
    } catch (err: any) {
      setStatusMessage({
        type: "error",
        text: "Failed to save settings: " + err.message,
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl pb-16">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900">Settings & Delivery Engine</h1>
        <p className="text-sm text-slate-500 mt-1">
          Connect your Gmail account via Google App Password or custom SMTP to dispatch unlimited bulk emails.
        </p>
      </div>

      {statusMessage && (
        <div
          className={`p-3.5 border text-xs rounded-xl flex items-center gap-2.5 transition-all ${
            statusMessage.type === "success"
              ? "bg-emerald-50 border-emerald-200 text-emerald-800"
              : "bg-rose-50 border-rose-200 text-rose-800"
          }`}
        >
          {statusMessage.type === "success" ? (
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
          ) : (
            <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
          )}
          <span className="font-medium">{statusMessage.text}</span>
        </div>
      )}

      {/* Profile Overview Card */}
      <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-4">
        <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
          <User className="w-4 h-4 text-slate-600" />
          Operator Account
        </h2>

        <div className="flex items-center gap-4">
          {profile?.photoURL || user?.photoURL ? (
            <img
              src={profile?.photoURL || user?.photoURL!}
              alt="Profile"
              className="w-12 h-12 rounded-full border border-slate-300 object-cover"
            />
          ) : (
            <div className="w-12 h-12 rounded-full bg-blue-100 text-blue-700 flex items-center justify-center font-bold text-base">
              {(profile?.displayName || user?.displayName || "U").charAt(0).toUpperCase()}
            </div>
          )}

          <div>
            <p className="font-bold text-sm text-slate-900">
              {profile?.displayName || user?.displayName || "Email Operator"}
            </p>
            <p className="text-xs text-slate-500 font-mono">
              {profile?.email || user?.email || ""}
            </p>
            <div className="mt-1 flex items-center gap-2">
              <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200">
                Google Authenticated
              </span>
              {userId && <span className="text-[10px] text-slate-400">UID: {userId}</span>}
            </div>
          </div>
        </div>
      </div>

      {/* Main Settings Form */}
      <form onSubmit={handleSaveSettings} className="space-y-6">
        {/* Sending Service Engine Selection */}
        <div className="bg-white p-6 rounded-xl border border-blue-200 shadow-sm space-y-5 bg-gradient-to-b from-blue-50/20 to-white">
          <div className="flex items-start justify-between border-b border-slate-100 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <Server className="w-5 h-5 text-blue-600" />
                <h2 className="text-base font-bold text-slate-900">Email Sending Engine</h2>
                <span className="text-[10px] font-bold uppercase tracking-wider bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded-full border border-emerald-200">
                  Zero Third-Party Quotas
                </span>
              </div>
              <p className="text-xs text-slate-600 mt-1">
                Select how you dispatch emails. Connect directly via Google App Password for effortless Gmail sending, or enter custom SMTP credentials.
              </p>
            </div>
          </div>

          {/* Engine Selector Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {/* Google App Password (Gmail) Card */}
            <div
              onClick={() => {
                setDeliveryMethod("gmail_app_password");
                if (gmailEmail && !fromEmail) setFromEmail(gmailEmail);
              }}
              className={`p-4 rounded-xl border-2 cursor-pointer transition-all ${
                deliveryMethod === "gmail_app_password"
                  ? "border-blue-600 bg-blue-50/50 shadow-sm"
                  : "border-slate-200 hover:border-slate-300 bg-white"
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-bold text-sm text-slate-900 flex items-center gap-2">
                  <div className="w-5 h-5 rounded-full bg-red-100 flex items-center justify-center text-red-600 text-xs font-black">
                    G
                  </div>
                  Gmail (Google App Password)
                </span>
                {deliveryMethod === "gmail_app_password" && (
                  <Check className="w-4 h-4 text-blue-600 font-bold" />
                )}
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                Connect your personal or Workspace Gmail using a 16-character Google App Password. Instant setup, high inbox delivery.
              </p>
              <div className="mt-2 flex items-center gap-1.5 text-[11px] text-blue-700 font-medium">
                <Sparkles className="w-3.5 h-3.5" />
                <span>Recommended for all senders</span>
              </div>
            </div>

            {/* Custom SMTP Server Card */}
            <div
              onClick={() => setDeliveryMethod("custom_smtp")}
              className={`p-4 rounded-xl border-2 cursor-pointer transition-all ${
                deliveryMethod === "custom_smtp"
                  ? "border-blue-600 bg-blue-50/50 shadow-sm"
                  : "border-slate-200 hover:border-slate-300 bg-white"
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-bold text-sm text-slate-900 flex items-center gap-1.5">
                  <Zap className="w-4 h-4 text-amber-500 fill-amber-500" />
                  Custom SMTP Server
                </span>
                {deliveryMethod === "custom_smtp" && (
                  <Check className="w-4 h-4 text-blue-600 font-bold" />
                )}
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                Connect any external mail server (AWS SES, Brevo, Postmark, or private VPS host). Fully customizable host and ports.
              </p>
            </div>
          </div>

          {/* GMAIL APP PASSWORD CONFIGURATION PANEL */}
          {deliveryMethod === "gmail_app_password" && (
            <div className="p-5 bg-slate-50/80 border border-slate-200 rounded-xl space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-1.5">
                  <KeyRound className="w-3.5 h-3.5 text-blue-600" />
                  Gmail Connection Credentials
                </span>

                <button
                  type="button"
                  onClick={() => setShowHelpGuide(!showHelpGuide)}
                  className="text-[11px] font-semibold text-blue-600 hover:text-blue-800 flex items-center gap-1 hover:underline"
                >
                  <HelpCircle className="w-3.5 h-3.5" />
                  <span>{showHelpGuide ? "Hide instructions" : "How to generate App Password?"}</span>
                </button>
              </div>

              {/* Step-by-Step Google App Password Tutorial Box */}
              {showHelpGuide && (
                <div className="p-4 bg-blue-50/60 border border-blue-200 rounded-xl text-xs space-y-2 text-slate-700">
                  <p className="font-bold text-blue-900 flex items-center gap-1.5">
                    <Info className="w-4 h-4 text-blue-600" />
                    How to get your 16-character Google App Password:
                  </p>
                  <ol className="list-decimal list-inside space-y-1 pl-1 text-[11.5px] leading-relaxed">
                    <li>
                      Go to your{" "}
                      <a
                        href="https://myaccount.google.com/security"
                        target="_blank"
                        rel="noreferrer"
                        className="text-blue-600 font-semibold underline inline-flex items-center gap-0.5"
                      >
                        Google Account Security <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                    </li>
                    <li>Ensure <strong>2-Step Verification</strong> is switched <strong>ON</strong>.</li>
                    <li>
                      Open the{" "}
                      <a
                        href="https://myaccount.google.com/apppasswords"
                        target="_blank"
                        rel="noreferrer"
                        className="text-blue-600 font-semibold underline inline-flex items-center gap-0.5"
                      >
                        App Passwords page <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                    </li>
                    <li>Enter <strong>MailForge</strong> in the app name box and click <strong>Create</strong>.</li>
                    <li>Copy the 16-character code (e.g. <code>abcd efgh ijkl mnop</code>) and paste it below.</li>
                  </ol>
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Gmail Address
                  </label>
                  <input
                    type="email"
                    value={gmailEmail}
                    onChange={(e) => {
                      setGmailEmail(e.target.value);
                      if (!fromEmail || fromEmail === gmailEmail) {
                        setFromEmail(e.target.value);
                      }
                    }}
                    placeholder="yourname@gmail.com"
                    className="w-full px-3 py-2 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 bg-white font-mono"
                    required
                  />
                  <p className="text-[11px] text-slate-500 mt-1">
                    Emails will be delivered from this Gmail account via SSL (Port 465).
                  </p>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="block text-xs font-semibold text-slate-700">
                      Google App Password
                    </label>
                    <span className="text-[10px] text-slate-400 font-mono">16 characters</span>
                  </div>

                  <div className="relative">
                    <input
                      type={showGmailPassword ? "text" : "password"}
                      value={gmailAppPassword}
                      onChange={(e) => setGmailAppPassword(e.target.value)}
                      placeholder="xxxx xxxx xxxx xxxx"
                      className="w-full px-3 py-2 pr-10 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 bg-white font-mono tracking-wider"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowGmailPassword(!showGmailPassword)}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                    >
                      {showGmailPassword ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                  <p className="text-[11px] text-slate-500 mt-1">
                    Spaces will be automatically removed when authenticating.
                  </p>
                </div>
              </div>

              {/* Actions & Verification */}
              <div className="pt-2 flex flex-wrap items-center justify-between gap-3 border-t border-slate-200">
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleTestConnection}
                    disabled={testingConnection || !gmailEmail || !gmailAppPassword}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold bg-white hover:bg-slate-100 text-slate-700 border border-slate-300 rounded-lg transition-colors shadow-xs disabled:opacity-50"
                  >
                    <Activity className="w-3.5 h-3.5 text-blue-600" />
                    <span>{testingConnection ? "Verifying..." : "Test Gmail Connection"}</span>
                  </button>

                  <button
                    type="button"
                    onClick={handleSendTestMessage}
                    disabled={sendingTestEmail || !gmailEmail || !gmailAppPassword}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 rounded-lg transition-colors shadow-xs disabled:opacity-50"
                  >
                    <Send className="w-3.5 h-3.5" />
                    <span>{sendingTestEmail ? "Sending..." : "Send Test Email"}</span>
                  </button>
                </div>

                <span className="text-[11px] text-slate-500">
                  Dispatcher: <strong className="text-slate-700">smtp.gmail.com:465 (SSL)</strong>
                </span>
              </div>
            </div>
          )}

          {/* CUSTOM SMTP CONFIGURATION DETAILS */}
          {deliveryMethod === "custom_smtp" && (
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                  SMTP Server Credentials
                </span>
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-slate-500 text-[11px]">Quick Presets:</span>
                  <button
                    type="button"
                    onClick={() => applyPreset("brevo")}
                    className="px-2 py-0.5 text-[11px] font-medium bg-white hover:bg-slate-100 border border-slate-300 rounded text-slate-700 transition-colors"
                  >
                    Brevo
                  </button>
                  <button
                    type="button"
                    onClick={() => applyPreset("postmark")}
                    className="px-2 py-0.5 text-[11px] font-medium bg-white hover:bg-slate-100 border border-slate-300 rounded text-slate-700 transition-colors"
                  >
                    Postmark
                  </button>
                  <button
                    type="button"
                    onClick={() => applyPreset("custom")}
                    className="px-2 py-0.5 text-[11px] font-medium bg-white hover:bg-slate-100 border border-slate-300 rounded text-slate-700 transition-colors"
                  >
                    Custom
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="sm:col-span-2">
                  <label className="block text-[11px] font-semibold text-slate-700 mb-1">
                    SMTP Host / Server
                  </label>
                  <input
                    type="text"
                    value={smtpHost}
                    onChange={(e) => setSmtpHost(e.target.value)}
                    placeholder="e.g. smtp.mailgun.org or mail.yourdomain.com"
                    className="w-full px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 bg-white font-mono"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-semibold text-slate-700 mb-1">
                    Port
                  </label>
                  <input
                    type="number"
                    value={smtpPort}
                    onChange={(e) => setSmtpPort(Number(e.target.value))}
                    className="w-full px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 bg-white font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-semibold text-slate-700 mb-1">
                    Username / SMTP User
                  </label>
                  <input
                    type="text"
                    value={smtpUser}
                    onChange={(e) => setSmtpUser(e.target.value)}
                    placeholder="e.g. apikey or user@domain.com"
                    className="w-full px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 bg-white font-mono"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-semibold text-slate-700 mb-1">
                    Password / API Secret
                  </label>
                  <div className="relative">
                    <input
                      type={showSmtpPassword ? "text" : "password"}
                      value={smtpPass}
                      onChange={(e) => setSmtpPass(e.target.value)}
                      placeholder="Enter SMTP password or API token"
                      className="w-full px-3 py-1.5 pr-10 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 bg-white font-mono"
                    />
                    <button
                      type="button"
                      onClick={() => setShowSmtpPassword(!showSmtpPassword)}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                    >
                      {showSmtpPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between pt-2">
                <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-700">
                  <input
                    type="checkbox"
                    checked={smtpSecure}
                    onChange={(e) => setSmtpSecure(e.target.checked)}
                    className="rounded border-slate-300 text-blue-600 focus:ring-blue-500 w-3.5 h-3.5"
                  />
                  <span>Use SSL/TLS (Default on Port 465)</span>
                </label>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleTestConnection}
                    disabled={testingConnection || !smtpHost || !smtpUser}
                    className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-semibold bg-white hover:bg-slate-100 text-slate-700 border border-slate-300 rounded-lg transition-colors shadow-xs disabled:opacity-50"
                  >
                    <Activity className="w-3.5 h-3.5 text-blue-600" />
                    <span>{testingConnection ? "Testing..." : "Test Connection"}</span>
                  </button>

                  <button
                    type="button"
                    onClick={handleSendTestMessage}
                    disabled={sendingTestEmail || !smtpHost || !smtpUser}
                    className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-semibold bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 rounded-lg transition-colors shadow-xs disabled:opacity-50"
                  >
                    <Send className="w-3.5 h-3.5" />
                    <span>{sendingTestEmail ? "Sending..." : "Send Test Email"}</span>
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Connection Test Status Feedback */}
          {testResult && (
            <div
              className={`p-3 text-xs rounded-lg border flex items-start gap-2 ${
                testResult.success
                  ? "bg-emerald-50 border-emerald-200 text-emerald-800"
                  : "bg-rose-50 border-rose-200 text-rose-800"
              }`}
            >
              {testResult.success ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
              ) : (
                <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
              )}
              <div className="space-y-1">
                <span className="font-semibold block">
                  {testResult.success ? "Authentication Successful" : "Authentication Error"}
                </span>
                <span className="leading-relaxed">{testResult.message}</span>
              </div>
            </div>
          )}

          {/* Test Email Sent Status Feedback */}
          {testEmailResult && (
            <div
              className={`p-3 text-xs rounded-lg border flex items-start gap-2 ${
                testEmailResult.success
                  ? "bg-emerald-50 border-emerald-200 text-emerald-800"
                  : "bg-rose-50 border-rose-200 text-rose-800"
              }`}
            >
              {testEmailResult.success ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
              ) : (
                <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
              )}
              <span className="font-medium">{testEmailResult.message}</span>
            </div>
          )}
        </div>

        {/* Sender Identity & Defaults */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4">
          <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
            <Mail className="w-4 h-4 text-slate-600" />
            Default Dispatcher Identity
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                From Name
              </label>
              <input
                type="text"
                value={fromName}
                onChange={(e) => setFromName(e.target.value)}
                placeholder="e.g. MailForge Team"
                className="w-full px-3 py-2 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                From Email Address
              </label>
              <input
                type="email"
                value={fromEmail}
                onChange={(e) => setFromEmail(e.target.value)}
                placeholder="you@gmail.com"
                className="w-full px-3 py-2 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">
              Default Reply-To (Optional)
            </label>
            <input
              type="email"
              value={replyTo}
              onChange={(e) => setReplyTo(e.target.value)}
              placeholder="replies@example.com"
              className="w-full px-3 py-2 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 font-mono"
            />
          </div>
        </div>

        {/* Telemetry, Click & Open Tracking */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4">
          <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
            <Activity className="w-4 h-4 text-slate-600" />
            Real-Time Deliverability Telemetry
          </h2>

          <div className="space-y-3">
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={trackOpens}
                onChange={(e) => setTrackOpens(e.target.checked)}
                className="mt-0.5 rounded border-slate-300 text-blue-600 focus:ring-blue-500 w-4 h-4"
              />
              <div>
                <p className="text-xs font-semibold text-slate-900">Inject Invisible 1x1 Open Tracking Pixel</p>
                <p className="text-[11px] text-slate-500">
                  Tracks individual recipient open timestamps, device user agents, and IP locations.
                </p>
              </div>
            </label>

            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={trackClicks}
                onChange={(e) => setTrackClicks(e.target.checked)}
                className="mt-0.5 rounded border-slate-300 text-blue-600 focus:ring-blue-500 w-4 h-4"
              />
              <div>
                <p className="text-xs font-semibold text-slate-900">Enable High-Precision Click Tracking</p>
                <p className="text-[11px] text-slate-500">
                  Automatically rewrites hyperlinks to capture clicks and immediate redirect to destination URL.
                </p>
              </div>
            </label>

            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={autoAppendUnsubscribe}
                onChange={(e) => setAutoAppendUnsubscribe(e.target.checked)}
                className="mt-0.5 rounded border-slate-300 text-blue-600 focus:ring-blue-500 w-4 h-4"
              />
              <div>
                <p className="text-xs font-semibold text-slate-900">Automated One-Click Unsubscribe Footer</p>
                <p className="text-[11px] text-slate-500">
                  Ensures full CAN-SPAM and GDPR compliance by automatically appending an unsubscribe link.
                </p>
              </div>
            </label>
          </div>
        </div>

        {/* Timezone Configuration */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4">
          <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
            <Clock className="w-4 h-4 text-slate-600" />
            Scheduling & Timezone
          </h2>

          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">
              Campaign Timezone
            </label>
            <select
              value={timezone}
              onChange={(e) => setTimezone(e.target.value)}
              className="w-full sm:w-64 px-3 py-2 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 bg-white"
            >
              <option value="UTC">UTC (Universal Time)</option>
              <option value="America/New_York">America/New_York (EST)</option>
              <option value="America/Los_Angeles">America/Los_Angeles (PST)</option>
              <option value="Europe/London">Europe/London (GMT)</option>
              <option value="Asia/Kolkata">Asia/Kolkata (IST)</option>
            </select>
          </div>
        </div>

        {/* Save Configuration Button */}
        <div className="flex justify-end pt-2">
          <button
            type="submit"
            disabled={saving}
            className="inline-flex items-center gap-2 px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold shadow-sm transition-all disabled:opacity-50"
          >
            <Save className="w-4 h-4" />
            <span>{saving ? "Saving Configuration..." : "Save Settings"}</span>
          </button>
        </div>
      </form>
    </div>
  );
}
