import { NextRequest, NextResponse } from "next/server";
import { readEmailLink } from "@/lib/email/links";
import { recordTracking } from "@/lib/server/tracking";
import { apiError } from "@/lib/server/api";

export async function GET(req: NextRequest) {
  try {
    const link = readEmailLink(req.nextUrl.searchParams.get("token") || "", "click");
    try { await recordTracking(link); }
    catch { console.error("Click tracking is temporarily unavailable"); }
    // URLSearchParams and the signed payload have already been decoded exactly once.
    return NextResponse.redirect(link.url!, { status: 302, headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" } });
  } catch (error) { return apiError(error); }
}
