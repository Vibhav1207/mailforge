import { NextRequest, NextResponse } from "next/server";
import { readEmailLink } from "@/lib/email/links";
import { recordTracking } from "@/lib/server/tracking";

const PIXEL = Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64");

export async function GET(req: NextRequest) {
  const token = req.nextUrl.searchParams.get("token");
  if (token) {
    try { await recordTracking(readEmailLink(token, "open")); }
    catch { /* A tracking failure must not break the image in the recipient's email. */ }
  }
  return new NextResponse(new Uint8Array(PIXEL), { headers: {
    "Content-Type": "image/gif", "Content-Length": String(PIXEL.length),
    "Cache-Control": "no-store, no-cache, must-revalidate", "X-Content-Type-Options": "nosniff",
  } });
}
