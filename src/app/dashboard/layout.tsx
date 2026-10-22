"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/context/auth-context";
import {
  LayoutDashboard,
  Send,
  Users,
  Megaphone,
  FileCode2,
  History,
  Settings,
  LogOut,
  Mail,
  Menu,
  X,
  ShieldCheck,
  ExternalLink,
  ChevronRight,
  User as UserIcon,
  Sparkles,
  Globe,
  Key,
} from "lucide-react";

const NAVIGATION_ITEMS = [
  { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
  { name: "Compose Email", href: "/dashboard/compose", icon: Send },
  { name: "Contacts", href: "/dashboard/contacts", icon: Users },
  { name: "Campaigns", href: "/dashboard/campaigns", icon: Megaphone },
  { name: "Email Templates", href: "/dashboard/templates", icon: FileCode2 },
  { name: "Sending History", href: "/dashboard/history", icon: History },
  { name: "Domains", href: "/dashboard/domains", icon: Globe },
  { name: "API Keys", href: "/dashboard/api-keys", icon: Key },
  { name: "Settings", href: "/dashboard/settings", icon: Settings },
];

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { user, profile, loading, signOut } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Authentication protection
  React.useEffect(() => {
    if (!loading && !user && !profile) {
      router.push("/");
    }
  }, [user, profile, loading, router]);

  const handleSignOut = async () => {
    await signOut();
    router.push("/");
  };

  const displayName = profile?.displayName || user?.displayName || "Email Operator";
  const displayEmail = profile?.email || user?.email || "";
  const photoUrl = profile?.photoURL || user?.photoURL;

  return (
    <div className="min-h-screen bg-slate-50 flex">
      {/* Mobile Drawer Overlay */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 z-40 bg-slate-900/50 backdrop-blur-sm lg:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar Component */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-64 bg-white border-r border-slate-200 transform transition-transform duration-200 ease-in-out lg:translate-x-0 lg:static lg:inset-auto flex flex-col justify-between ${
          mobileMenuOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div>
          {/* Logo & Workspace Brand */}
          <div className="h-16 px-6 border-b border-slate-200 flex items-center justify-between">
            <Link href="/dashboard" className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center text-white shadow-sm font-bold">
                <Mail className="w-4 h-4" />
              </div>
              <div>
                <span className="font-bold text-slate-900 tracking-tight">MailForge</span>
                <span className="block text-[10px] uppercase font-semibold text-slate-600 tracking-wider">
                  Bulk Infrastructure
                </span>
              </div>
            </Link>
            <button
              onClick={() => setMobileMenuOpen(false)}
              className="lg:hidden p-1.5 rounded-md text-slate-500 hover:bg-slate-100"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Quick Action Button */}
          <div className="p-4">
            <Link
              href="/dashboard/compose"
              onClick={() => setMobileMenuOpen(false)}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-semibold shadow-sm transition-all"
            >
              <Send className="w-4 h-4" />
              <span>Compose Campaign</span>
            </Link>
          </div>

          {/* Navigation Links */}
          <nav className="px-3 space-y-1">
            {NAVIGATION_ITEMS.map((item) => {
              const isActive =
                item.href === "/dashboard"
                  ? pathname === "/dashboard"
                  : pathname?.startsWith(item.href);
              const Icon = item.icon;

              return (
                <Link
                  key={item.name}
                  href={item.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className={`flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                    isActive
                      ? "bg-blue-50 text-blue-700 font-semibold"
                      : "text-slate-600 hover:bg-slate-100/80 hover:text-slate-900"
                  }`}
                >
                  <Icon
                    className={`w-4 h-4 shrink-0 ${
                      isActive ? "text-blue-600" : "text-slate-600"
                    }`}
                  />
                  <span>{item.name}</span>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* User Profile & Footer Area */}
        <div className="p-4 border-t border-slate-200 bg-slate-50/50">
          <div className="flex items-center gap-3 mb-3">
            {photoUrl ? (
              <img
                src={photoUrl}
                alt={displayName}
                className="w-9 h-9 rounded-full border border-slate-300 object-cover"
              />
            ) : (
              <div className="w-9 h-9 rounded-full bg-slate-200 border border-slate-300 flex items-center justify-center text-slate-600 font-semibold text-xs">
                {displayName.charAt(0).toUpperCase()}
              </div>
            )}
            <div className="flex-1 min-w-0">
              <p className="text-xs font-semibold text-slate-900 truncate">{displayName}</p>
              <p className="text-[11px] text-slate-600 truncate">{displayEmail}</p>
            </div>
          </div>

          <button
            onClick={handleSignOut}
            className="w-full flex items-center justify-center gap-2 py-2 px-3 text-xs font-medium text-slate-700 hover:text-red-700 hover:bg-red-50 rounded-lg border border-slate-200 transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Sign Out</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Mobile Header Bar */}
        <header className="h-16 lg:hidden border-b border-slate-200 bg-white px-4 flex items-center justify-between">
          <button
            onClick={() => setMobileMenuOpen(true)}
            className="p-2 rounded-lg text-slate-600 hover:bg-slate-100"
          >
            <Menu className="w-5 h-5" />
          </button>
          <div className="flex items-center gap-2 font-bold text-slate-900">
            <Mail className="w-4 h-4 text-blue-600" />
            <span>MailForge</span>
          </div>
          <div className="w-8" />
        </header>

        {/* Content Container */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
