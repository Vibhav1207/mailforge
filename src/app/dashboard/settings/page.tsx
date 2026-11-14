"use client";

import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import { useAuth } from "@/context/auth-context";
import { updateUserSettings } from "@/lib/store/db-service";
import { apiFetch } from "@/lib/api-client";
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
      setFromName(profile.settings.defaultFromName || profile.displayName || user?.displayName || "Postvane Sender");
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
      const defaultMail = user?.email || "";
      setGmailEmail(defaultMail);
      setFromEmail(defaultMail);
      setFromName(user?.displayName || "Postvane Dispatcher");
    }
  }, [profile, user]);

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
      const res = await apiFetch("/api/smtp/verify", {
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
      const res = await apiFetch("/api/send-test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          to: target,
          subject: "Test Dispatch from Postvane",
          htmlContent: `
            <div style="font-family: sans-serif; padding: 24px; border: 1px solid #262A2E; border-radius: 8px; background: #ffffff; color: #111827;">
              <h2 style="color: #111827; margin-top: 0;">Postvane Delivery Verified</h2>
              <p>Your <strong>${isGmailMode ? "Gmail Google App Password" : "Custom SMTP"}</strong> configuration is functioning correctly.</p>
              <p style="color: #64748b; font-size: 13px;">Sender: ${fromName} &lt;${fromEmail || userEmail}&gt;</p>
              <p style="color: #64748b; font-size: 12px; margin-top: 24px;">Sent via Postvane Production Engine.</p>
            </div>
          `,
          fromName: fromName || "Postvane Dispatcher",
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
        defaultFromName: fromName.trim() || "Postvane Team",
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
        text: "Configuration saved successfully. Delivery credentials are active.",
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
        <h1 className="text-xl font-medium tracking-tight text-white">Settings & Delivery Transport</h1>
        <p className="text-xs text-zinc-400 font-mono mt-1">
          Configure Gmail App Passwords, external SMTP relays, and default sender identity.
        </p>
      </div>

      <AnimatePresence>
        {statusMessage && (
          <motion.div
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            className={`p-3.5 border text-xs rounded-xl flex items-center gap-2.5 transition-all font-mono ${
              statusMessage.type === "success"
                ? "bg-emerald-950/40 border-emerald-500/30 text-emerald-400"
                : "bg-red-950/40 border-red-500/30 text-red-400"
            }`}
          >
            {statusMessage.type === "success" ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : (
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            )}
            <span>{statusMessage.text}</span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Profile Overview Card */}
      <div className="bg-[#111315] p-5 rounded-xl border border-[#262A2E] space-y-4">
        <h2 className="text-xs font-mono uppercase tracking-wider text-zinc-400 flex items-center gap-2">
          <User className="w-3.5 h-3.5" />
          Operator Account
        </h2>

        <div className="flex items-center gap-4">
          {profile?.photoURL || user?.photoURL ? (
            <img
              src={profile?.photoURL || user?.photoURL!}
              alt="Profile"
              className="w-11 h-11 rounded-full border border-[#262A2E] object-cover"
            />
          ) : (
            <div className="w-11 h-11 rounded-full bg-[#171A1D] border border-[#262A2E] text-white flex items-center justify-center font-bold text-sm">
              {(profile?.displayName || user?.displayName || "U").charAt(0).toUpperCase()}
            </div>
          )}

          <div>
            <p className="font-medium text-sm text-white">
              {profile?.displayName || user?.displayName || "Email Operator"}
            </p>
            <p className="text-xs text-zinc-400 font-mono mt-0.5">
              {profile?.email || user?.email || ""}
            </p>
            <div className="mt-1 flex items-center gap-2 font-mono">
              <span className="text-[10px] uppercase px-2 py-0.5 rounded bg-[#171A1D] text-zinc-300 border border-[#262A2E]">
                Google Authenticated
              </span>
              {userId && <span className="text-[10px] text-zinc-600">UID: {userId.slice(0, 12)}...</span>}
            </div>
          </div>
        </div>
      </div>

      {/* Main Settings Form */}
      <form onSubmit={handleSaveSettings} className="space-y-6">
        {/* Sending Service Engine Selection */}
        <div className="bg-[#111315] p-5 rounded-xl border border-[#262A2E] space-y-4">
          <div className="flex items-start justify-between border-b border-[#262A2E] pb-3">
            <div>
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-zinc-400" />
                <h2 className="text-sm font-medium text-white">Email Delivery Transport</h2>
              </div>
              <p className="text-xs text-zinc-400 font-mono mt-1">
                Select your dispatch method. Connect via Google App Password for Gmail sending or configure a custom SMTP server.
              </p>
            </div>
          </div>

          {/* Engine Selector Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {/* Google App Password (Gmail) Card */}
            <motion.div
              whileHover={{ scale: 1.01 }}
              whileTap={{ scale: 0.99 }}
              onClick={() => {
                setDeliveryMethod("gmail_app_password");
                if (gmailEmail && !fromEmail) setFromEmail(gmailEmail);
              }}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                deliveryMethod === "gmail_app_password"
                  ? "border-white bg-[#171A1D]"
                  : "border-[#262A2E] hover:border-zinc-600 bg-[#0D0F11]"
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-medium text-xs text-white flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-white text-black flex items-center justify-center text-[10px] font-bold">
                    G
                  </div>
                  Gmail (App Password)
                </span>
                {deliveryMethod === "gmail_app_password" && (
                  <Check className="w-3.5 h-3.5 text-white" />
                )}
              </div>
              <p className="text-xs text-zinc-400 leading-relaxed font-mono">
                Connect your personal or Workspace Gmail via a 16-character Google App Password. Port 465 SSL.
              </p>
            </motion.div>

            {/* Custom SMTP Server Card */}
            <motion.div
              whileHover={{ scale: 1.01 }}
              whileTap={{ scale: 0.99 }}
              onClick={() => setDeliveryMethod("custom_smtp")}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                deliveryMethod === "custom_smtp"
                  ? "border-white bg-[#171A1D]"
                  : "border-[#262A2E] hover:border-zinc-600 bg-[#0D0F11]"
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-medium text-xs text-white flex items-center gap-1.5">
                  <Zap className="w-3.5 h-3.5 text-zinc-400" />
                  Custom SMTP Relay
                </span>
                {deliveryMethod === "custom_smtp" && (
                  <Check className="w-3.5 h-3.5 text-white" />
                )}
              </div>
              <p className="text-xs text-zinc-400 leading-relaxed font-mono">
                Connect any external mail server (AWS SES, Brevo, Postmark, or private VPS host).
              </p>
            </motion.div>
          </div>

          {/* GMAIL APP PASSWORD CONFIGURATION PANEL */}
          {deliveryMethod === "gmail_app_password" && (
            <div className="p-4 bg-[#171A1D] border border-[#262A2E] rounded-xl space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
                  <KeyRound className="w-3.5 h-3.5" />
                  Gmail Credentials
                </span>

                <button
                  type="button"
                  onClick={() => setShowHelpGuide(!showHelpGuide)}
                  className="text-[11px] font-mono text-zinc-400 hover:text-white flex items-center gap-1"
                >
                  <HelpCircle className="w-3.5 h-3.5" />
                  <span>{showHelpGuide ? "Hide instructions" : "How to generate App Password?"}</span>
                </button>
              </div>

              {/* Step-by-Step Google App Password Tutorial Box */}
              {showHelpGuide && (
                <div className="p-4 bg-[#111315] border border-[#262A2E] rounded-xl text-xs space-y-2 text-zinc-300 font-mono">
                  <p className="font-medium text-white flex items-center gap-1.5">
                    <Info className="w-4 h-4 text-zinc-400" />
                    How to get your 16-character Google App Password:
                  </p>
                  <ol className="list-decimal list-inside space-y-1 pl-1 text-[11px] leading-relaxed text-zinc-400">
                    <li>
                      Visit{" "}
                      <a
                        href="https://myaccount.google.com/security"
                        target="_blank"
                        rel="noreferrer"
                        className="text-white underline inline-flex items-center gap-0.5"
                      >
                        Google Account Security <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                    </li>
                    <li>Ensure <strong>2-Step Verification</strong> is switched ON.</li>
                    <li>
                      Open{" "}
                      <a
                        href="https://myaccount.google.com/apppasswords"
                        target="_blank"
                        rel="noreferrer"
                        className="text-white underline inline-flex items-center gap-0.5"
                      >
                        App Passwords <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                    </li>
                    <li>Enter <strong>Postvane</strong> and click Create.</li>
                    <li>Copy the 16-character code and paste below.</li>
                  </ol>
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-[11px] font-mono text-zinc-400 mb-1">
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
                    className="w-full px-3 py-1.5 text-xs bg-[#111315] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none font-mono"
                    required
                  />
                  <p className="text-[10px] text-zinc-500 font-mono mt-1">
                    Dispatched via smtp.gmail.com:465 (SSL).
                  </p>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="block text-[11px] font-mono text-zinc-400">
                      Google App Password
                    </label>
                    <span className="text-[10px] text-zinc-600 font-mono">16 characters</span>
                  </div>

                  <div className="relative">
                    <input
                      type={showGmailPassword ? "text" : "password"}
                      value={gmailAppPassword}
                      onChange={(e) => setGmailAppPassword(e.target.value)}
                      placeholder="xxxx xxxx xxxx xxxx"
                      className="w-full px-3 py-1.5 pr-10 text-xs bg-[#111315] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none font-mono tracking-wider"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowGmailPassword(!showGmailPassword)}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-white"
                    >
                      {showGmailPassword ? (
                        <EyeOff className="w-3.5 h-3.5" />
                      ) : (
                        <Eye className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>
              </div>

              {/* Actions & Verification */}
              <div className="pt-2 flex flex-wrap items-center justify-between gap-3 border-t border-[#262A2E]">
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleTestConnection}
                    disabled={testingConnection || !gmailEmail || !gmailAppPassword}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono text-zinc-300 bg-[#111315] hover:border-zinc-500 hover:text-white border border-[#262A2E] rounded-lg transition-colors disabled:opacity-40"
                  >
                    <Activity className="w-3.5 h-3.5 text-zinc-400" />
                    <span>{testingConnection ? "Verifying..." : "Test Connection"}</span>
                  </button>

                  <button
                    type="button"
                    onClick={handleSendTestMessage}
                    disabled={sendingTestEmail || !gmailEmail || !gmailAppPassword}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono text-zinc-300 bg-[#111315] hover:border-zinc-500 hover:text-white border border-[#262A2E] rounded-lg transition-colors disabled:opacity-40"
                  >
                    <Send className="w-3.5 h-3.5 text-zinc-400" />
                    <span>{sendingTestEmail ? "Sending..." : "Send Test Email"}</span>
                  </button>
                </div>

                <span className="text-[10px] text-zinc-500 font-mono">
                  smtp.gmail.com:465 (SSL)
                </span>
              </div>
            </div>
          )}

          {/* CUSTOM SMTP CONFIGURATION DETAILS */}
          {deliveryMethod === "custom_smtp" && (
            <div className="p-4 bg-[#171A1D] border border-[#262A2E] rounded-xl space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-400">
                  SMTP Server Credentials
                </span>
                <div className="flex items-center gap-2 text-xs font-mono">
                  <span className="text-zinc-500 text-[11px]">Presets:</span>
                  <button
                    type="button"
                    onClick={() => applyPreset("brevo")}
                    className="px-2 py-0.5 text-[11px] bg-[#111315] hover:bg-[#1D2125] border border-[#262A2E] rounded text-zinc-300 transition-colors"
                  >
                    Brevo
                  </button>
                  <button
                    type="button"
                    onClick={() => applyPreset("postmark")}
                    className="px-2 py-0.5 text-[11px] bg-[#111315] hover:bg-[#1D2125] border border-[#262A2E] rounded text-zinc-300 transition-colors"
                  >
                    Postmark
                  </button>
                  <button
                    type="button"
                    onClick={() => applyPreset("custom")}
                    className="px-2 py-0.5 text-[11px] bg-[#111315] hover:bg-[#1D2125] border border-[#262A2E] rounded text-zinc-300 transition-colors"
                  >
                    Custom
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="sm:col-span-2">
                  <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                    SMTP Host / Server
                  </label>
                  <input
                    type="text"
                    value={smtpHost}
                    onChange={(e) => setSmtpHost(e.target.value)}
                    placeholder="smtp.mailgun.org or mail.yourdomain.com"
                    className="w-full px-3 py-1.5 text-xs bg-[#111315] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none font-mono"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                    Port
                  </label>
                  <input
                    type="number"
                    value={smtpPort}
                    onChange={(e) => setSmtpPort(Number(e.target.value))}
                    className="w-full px-3 py-1.5 text-xs bg-[#111315] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                    Username / SMTP User
                  </label>
                  <input
                    type="text"
                    value={smtpUser}
                    onChange={(e) => setSmtpUser(e.target.value)}
                    placeholder="user@domain.com"
                    className="w-full px-3 py-1.5 text-xs bg-[#111315] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none font-mono"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                    Password / API Secret
                  </label>
                  <div className="relative">
                    <input
                      type={showSmtpPassword ? "text" : "password"}
                      value={smtpPass}
                      onChange={(e) => setSmtpPass(e.target.value)}
                      placeholder="SMTP password or secret"
                      className="w-full px-3 py-1.5 pr-10 text-xs bg-[#111315] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none font-mono"
                    />
                    <button
                      type="button"
                      onClick={() => setShowSmtpPassword(!showSmtpPassword)}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-white"
                    >
                      {showSmtpPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between pt-2">
                <label className="flex items-center gap-2 cursor-pointer text-xs font-mono text-zinc-300">
                  <input
                    type="checkbox"
                    checked={smtpSecure}
                    onChange={(e) => setSmtpSecure(e.target.checked)}
                    className="rounded bg-[#111315] border-[#262A2E] text-white focus:ring-0"
                  />
                  <span>SSL/TLS (Default Port 465)</span>
                </label>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleTestConnection}
                    disabled={testingConnection || !smtpHost || !smtpUser}
                    className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-mono text-zinc-300 bg-[#111315] hover:border-zinc-500 hover:text-white border border-[#262A2E] rounded-lg transition-colors disabled:opacity-40"
                  >
                    <Activity className="w-3.5 h-3.5 text-zinc-400" />
                    <span>{testingConnection ? "Testing..." : "Test"}</span>
                  </button>

                  <button
                    type="button"
                    onClick={handleSendTestMessage}
                    disabled={sendingTestEmail || !smtpHost || !smtpUser}
                    className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-mono text-zinc-300 bg-[#111315] hover:border-zinc-500 hover:text-white border border-[#262A2E] rounded-lg transition-colors disabled:opacity-40"
                  >
                    <Send className="w-3.5 h-3.5 text-zinc-400" />
                    <span>{sendingTestEmail ? "Sending..." : "Send Test Email"}</span>
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Connection Test Status Feedback */}
          {testResult && (
            <div
              className={`p-3 text-xs rounded-lg border flex items-start gap-2 font-mono ${
                testResult.success
                  ? "bg-emerald-950/40 border-emerald-500/30 text-emerald-400"
                  : "bg-red-950/40 border-red-500/30 text-red-400"
              }`}
            >
              {testResult.success ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              ) : (
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              )}
              <div className="space-y-0.5">
                <span className="font-medium block">
                  {testResult.success ? "Authentication Successful" : "Authentication Error"}
                </span>
                <span className="leading-relaxed text-[11px]">{testResult.message}</span>
              </div>
            </div>
          )}

          {/* Test Email Sent Status Feedback */}
          {testEmailResult && (
            <div
              className={`p-3 text-xs rounded-lg border flex items-start gap-2 font-mono ${
                testEmailResult.success
                  ? "bg-emerald-950/40 border-emerald-500/30 text-emerald-400"
                  : "bg-red-950/40 border-red-500/30 text-red-400"
              }`}
            >
              {testEmailResult.success ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              ) : (
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              )}
              <span className="font-medium">{testEmailResult.message}</span>
            </div>
          )}
        </div>

        {/* Sender Identity & Defaults */}
        <div className="bg-[#111315] p-5 rounded-xl border border-[#262A2E] space-y-4">
          <h2 className="text-xs font-mono uppercase tracking-wider text-zinc-400 flex items-center gap-2">
            <Mail className="w-3.5 h-3.5" />
            Default Dispatcher Identity
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                From Name
              </label>
              <input
                type="text"
                value={fromName}
                onChange={(e) => setFromName(e.target.value)}
                placeholder="Postvane Team"
                className="w-full px-3 py-1.5 text-xs bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                From Email Address
              </label>
              <input
                type="email"
                value={fromEmail}
                onChange={(e) => setFromEmail(e.target.value)}
                placeholder="you@gmail.com"
                className="w-full px-3 py-1.5 text-xs bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-[11px] font-mono text-zinc-400 mb-1">
              Default Reply-To (Optional)
            </label>
            <input
              type="email"
              value={replyTo}
              onChange={(e) => setReplyTo(e.target.value)}
              placeholder="replies@example.com"
              className="w-full px-3 py-1.5 text-xs bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none font-mono"
            />
          </div>
        </div>

        {/* Telemetry, Click & Open Tracking */}
        <div className="bg-[#111315] p-5 rounded-xl border border-[#262A2E] space-y-4">
          <h2 className="text-xs font-mono uppercase tracking-wider text-zinc-400 flex items-center gap-2">
            <Activity className="w-3.5 h-3.5" />
            Engagement & Compliance
          </h2>

          <div className="space-y-3 font-mono">
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={trackOpens}
                onChange={(e) => setTrackOpens(e.target.checked)}
                className="mt-0.5 rounded bg-[#171A1D] border-[#262A2E] text-white focus:ring-0"
              />
              <div>
                <p className="text-xs text-white">Inject 1x1 Open Tracking Pixel</p>
                <p className="text-[11px] text-zinc-500">
                  Captures individual open timestamps and user agents.
                </p>
              </div>
            </label>

            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={trackClicks}
                onChange={(e) => setTrackClicks(e.target.checked)}
                className="mt-0.5 rounded bg-[#171A1D] border-[#262A2E] text-white focus:ring-0"
              />
              <div>
                <p className="text-xs text-white">Enable Click Tracking Proxy</p>
                <p className="text-[11px] text-zinc-500">
                  Rewrites links to log click timestamps before redirecting.
                </p>
              </div>
            </label>

            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={autoAppendUnsubscribe}
                onChange={(e) => setAutoAppendUnsubscribe(e.target.checked)}
                className="mt-0.5 rounded bg-[#171A1D] border-[#262A2E] text-white focus:ring-0"
              />
              <div>
                <p className="text-xs text-white">One-Click Unsubscribe Footer</p>
                <p className="text-[11px] text-zinc-500">
                  Appends RFC 8058 compliant unsubscribe link to outgoing campaign emails.
                </p>
              </div>
            </label>
          </div>
        </div>

        {/* Timezone Configuration */}
        <div className="bg-[#111315] p-5 rounded-xl border border-[#262A2E] space-y-4">
          <h2 className="text-xs font-mono uppercase tracking-wider text-zinc-400 flex items-center gap-2">
            <Clock className="w-3.5 h-3.5" />
            Scheduling & Timezone
          </h2>

          <div>
            <label className="block text-[11px] font-mono text-zinc-400 mb-1">
              Campaign Timezone
            </label>
            <select
              value={timezone}
              onChange={(e) => setTimezone(e.target.value)}
              className="w-full sm:w-64 px-3 py-1.5 text-xs bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:outline-none font-mono"
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
          <motion.button
            whileHover={{ y: -1 }}
            whileTap={{ scale: 0.98 }}
            type="submit"
            disabled={saving}
            className="inline-flex items-center gap-2 px-5 py-2 bg-white hover:bg-zinc-200 text-black rounded-lg text-xs font-medium shadow-sm transition-all disabled:opacity-50"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{saving ? "Saving..." : "Save Configuration"}</span>
          </motion.button>
        </div>
      </form>
    </div>
  );
}
