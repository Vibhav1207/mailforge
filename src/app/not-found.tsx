import Link from "next/link";
import { ArrowLeft } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-[#08090A] text-[#F5F5F5] px-4 font-sans">
      <div className="max-w-md w-full text-center space-y-6">
        <div className="w-12 h-12 rounded-xl bg-[#111315] border border-[#262A2E] flex items-center justify-center text-white mx-auto shadow-sm">
          <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="m22 2-7 20-4-9-9-4Z" />
            <path d="M22 2 11 13" />
          </svg>
        </div>

        <div className="space-y-2">
          <h1 className="text-4xl font-medium tracking-tight text-white font-mono">404</h1>
          <h2 className="text-base font-medium text-zinc-300">Page Not Found</h2>
          <p className="text-xs text-zinc-400 font-mono">
            The requested resource doesn&apos;t exist or has been moved.
          </p>
        </div>

        <div>
          <Link
            href="/"
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-black bg-white hover:bg-zinc-200 rounded-lg shadow-sm transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Home</span>
          </Link>
        </div>
      </div>
    </div>
  );
}
