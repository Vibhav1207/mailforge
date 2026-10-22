import { NextRequest } from "next/server";
import { z } from "zod";
import { readEmailLink } from "@/lib/email/links";
import { apiError, json, parseJson, readBody } from "@/lib/server/api";
import { emailSchema } from "@/lib/server/validation";
import { unsubscribeRecipient } from "@/lib/server/unsubscribe";
import { ApiError } from "@/lib/server/errors";

const schema = z.object({ token: z.string().min(1).max(6000), email: emailSchema.optional() });

export async function GET(req: NextRequest) {
  try {
    const link = readEmailLink(req.nextUrl.searchParams.get("token") || "", "unsubscribe");
    // A GET only displays preferences: mail scanners must not unsubscribe recipients.
    return json({ email: link.email });
  } catch (error) { return apiError(error); }
}

export async function POST(req: NextRequest) {
  try {
    const queryToken = req.nextUrl.searchParams.get("token");
    let token: string;
    let email: string | undefined;
    if (queryToken && req.headers.get("content-type")?.startsWith("application/x-www-form-urlencoded")) {
      const body = new URLSearchParams(Buffer.from(await readBody(req, 1000)).toString("utf8"));
      if (body.get("List-Unsubscribe") !== "One-Click") throw new ApiError(400, "Invalid one-click unsubscribe request.", "INVALID_REQUEST");
      token = queryToken;
    } else {
      const input = await parseJson(req, schema, 8000);
      token = input.token;
      email = input.email;
    }
    const link = readEmailLink(token, "unsubscribe");
    if (email && email !== link.email) throw new ApiError(400, "This link belongs to a different email address.", "INVALID_EMAIL_LINK");
    await unsubscribeRecipient(link);
    return json({ success: true, message: "You have been unsubscribed from this sender." });
  } catch (error) { return apiError(error); }
}
