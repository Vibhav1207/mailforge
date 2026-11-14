"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/context/auth-context";
import { motion, AnimatePresence } from "motion/react";
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
  Globe,
  Key,
  Plus,
} from "lucide-react";
import { PageTransition } from "@/components/motion/PageTransition";

const NAVIGATION_ITEMS = [
  { name: "Overview", href: "/dashboard", icon: LayoutDashboard },
  { name: "Campaigns", href: "/dashboard/campaigns", icon: Megaphone },
  { name: "Compose", href: "/dashboard/compose", icon: Send },
  { name: "Contacts", href: "/dashboard/contacts", icon: Users },
  { name: "Templates", href: "/dashboard/templates", icon: FileCode2 },
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

  const displayName = profile?.displayName || user?.displayName || "Operator";
  const displayEmail = profile?.email || user?.email || "";
  const photoUrl = profile?.photoURL || user?.photoURL;

  return (
    <div className="min-h-screen bg-[#08090A] text-[#F5F5F5] flex font-sans selection:bg-white/10 selection:text-white">
      {/* Mobile Drawer Overlay */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm lg:hidden"
            onClick={() => setMobileMenuOpen(false)}
          />
        )}
      </AnimatePresence>

      {/* Sidebar Component */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-60 bg-[#0D0F11] border-r border-[#1C2024] transform transition-transform duration-200 ease-in-out lg:translate-x-0 lg:static lg:inset-auto flex flex-col justify-between ${
          mobileMenuOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex flex-col h-full justify-between">
          <div>
            {/* Logo & Workspace Brand */}
            <div className="h-16 px-5 border-b border-[#1C2024] flex items-center justify-between">
              <Link href="/dashboard" className="flex items-center gap-2.5 group">
                <motion.div
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  className="w-7 h-7 rounded-md bg-white flex items-center justify-center text-[#08090A] shadow-sm transition-transform"
                >
                  <Mail className="w-4 h-4 fill-current" />
                </motion.div>
                <div>
                  <span className="font-semibold text-sm text-[#F5F5F5] tracking-tight block">Postvane</span>
                  <span className="text-[10px] font-mono text-[#71717A] tracking-wider uppercase block">Console</span>
                </div>
              </Link>
              <button
                onClick={() => setMobileMenuOpen(false)}
                className="lg:hidden p-1.5 rounded-md text-[#A1A1AA] hover:text-white hover:bg-[#171A1D]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Quick Action Button: New Campaign */}
            <div className="px-3 pt-4 pb-2">
              <motion.div whileHover={{ y: -1 }} whileTap={{ scale: 0.97 }} transition={{ duration: 0.18 }}>
                <Link
                  href="/dashboard/compose"
                  className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 bg-white hover:bg-[#E5E7EB] text-[#08090A] rounded-md text-xs font-semibold shadow-sm transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>New Campaign</span>
                </Link>
              </motion.div>
            </div>

            {/* Navigation Links with animated active indicator */}
            <nav className="px-3 py-3 space-y-1">
              {NAVIGATION_ITEMS.map((item) => {
                const isActive = pathname === item.href || (item.href !== "/dashboard" && pathname.startsWith(item.href));
                const Icon = item.icon;

                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={() => setMobileMenuOpen(false)}
                    className={`group relative flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium transition-colors ${
                      isActive
                        ? "text-white"
                        : "text-[#A1A1AA] hover:text-[#F5F5F5] hover:bg-[#111315]/70"
                    }`}
                  >
                    {isActive && (
                      <motion.span
                        layoutId="active-sidebar-pill"
                        className="absolute inset-0 bg-[#171A1D] border border-[#262A2E] rounded-md -z-10"
                        transition={{ type: "spring", stiffness: 450, damping: 35 }}
                      />
                    )}
                    <Icon
                      className={`w-4 h-4 transition-transform duration-150 group-hover:translate-x-0.5 ${
                        isActive ? "text-white" : "text-[#71717A]"
                      }`}
                    />
                    <span>{item.name}</span>
                  </Link>
                );
              })}
            </nav>
          </div>

          {/* User Profile & Sign Out Footer */}
          <div className="p-3 border-t border-[#1C2024] bg-[#0D0F11]">
            <div className="flex items-center justify-between p-2 rounded-md bg-[#111315] border border-[#1C2024] hover:border-[#262A2E] transition-colors">
              <div className="flex items-center gap-2.5 min-w-0">
                {photoUrl ? (
                  <img
                    src={photoUrl}
                    alt={displayName}
                    className="w-7 h-7 rounded-full border border-[#262A2E] object-cover shrink-0"
                  />
                ) : (
                  <div className="w-7 h-7 rounded-full bg-[#171A1D] border border-[#262A2E] flex items-center justify-center text-xs font-semibold text-white shrink-0">
                    {displayName.charAt(0).toUpperCase()}
                  </div>
                )}
                <div className="min-w-0">
                  <p className="text-xs font-medium text-[#F5F5F5] truncate">{displayName}</p>
                  <p className="text-[10px] text-[#71717A] truncate font-mono">{displayEmail}</p>
                </div>
              </div>

              <motion.button
                whileHover={{ scale: 1.1 }}
                whileTap={{ scale: 0.95 }}
                onClick={handleSignOut}
                className="p-1.5 text-[#71717A] hover:text-[#EF4444] rounded hover:bg-[#171A1D] transition-colors"
                title="Sign Out"
              >
                <LogOut className="w-3.5 h-3.5" />
              </motion.button>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 min-h-screen">
        {/* Mobile Header Bar */}
        <header className="h-14 px-4 bg-[#0D0F11] border-b border-[#1C2024] flex items-center justify-between lg:hidden sticky top-0 z-30">
          <Link href="/dashboard" className="flex items-center gap-2">
            <div className="w-6 h-6 rounded bg-white flex items-center justify-center text-[#08090A]">
              <Mail className="w-3.5 h-3.5 fill-current" />
            </div>
            <span className="font-semibold text-sm text-[#F5F5F5]">Postvane</span>
          </Link>
          <button
            onClick={() => setMobileMenuOpen(true)}
            className="p-2 rounded-md text-[#A1A1AA] hover:text-white hover:bg-[#171A1D]"
          >
            <Menu className="w-5 h-5" />
          </button>
        </header>

        {/* Dashboard Dynamic Page View with Smooth Entrance */}
        <main className="flex-1 p-6 lg:p-8 max-w-7xl w-full mx-auto">
          <PageTransition key={pathname}>
            {children}
          </PageTransition>
        </main>
      </div>
    </div>
  );
}
