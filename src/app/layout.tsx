import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { AuthProvider } from "@/context/auth-context";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Postvane — Developer-First Email Platform",
  description:
    "A developer-friendly platform to run, automate, and scale your email outreach — with control, reliability, and real-time deliverability telemetry.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark h-full">
      <body
        className={`${geistSans.variable} ${geistMono.variable} font-sans h-full min-h-screen bg-[#08090A] text-[#F5F5F5] antialiased selection:bg-white/10 selection:text-white`}
      >
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
