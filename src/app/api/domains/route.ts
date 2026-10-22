import { NextRequest } from "next/server";
import { z } from "zod";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { apiError, json, parseJson } from "@/lib/server/api";
import {
  createNativeDomain,
  listNativeDomains,
  deleteNativeDomain,
  verifyNativeDomainDns,
} from "@/lib/server/domains";
import { rateLimit } from "@/lib/server/rate-limit";

export async function GET(req: NextRequest) {
  try {
    const user = await requireUser(req);
    await rateLimit(user.uid, "domains-get", 30);

    const domains = await listNativeDomains(user);

    return json({
      provider: "MailForge Native (DKIM + Self-Hosted)",
      domains,
    });
  } catch (error) {
    return apiError(error);
  }
}

export async function POST(req: NextRequest) {
  try {
    const user = await requireUser(req);
    await rateLimit(user.uid, "domains-add", 10);

    const input = await parseJson(
      req,
      z.object({
        domain: z
          .string()
          .trim()
          .toLowerCase()
          .min(3)
          .max(253)
          .regex(
            /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
            "Enter a valid domain name (e.g. acme.com or mail.acme.com)."
          ),
      })
    );

    const created = await createNativeDomain(user, input.domain);
    return json({ success: true, domain: created }, 201);
  } catch (error) {
    return apiError(error);
  }
}

export async function DELETE(req: NextRequest) {
  try {
    const user = await requireUser(req);
    await rateLimit(user.uid, "domains-del", 15);

    const url = new URL(req.url);
    const domainId = url.searchParams.get("id") || url.searchParams.get("domain");
    if (!domainId) {
      return json({ error: "Missing domain id parameter." }, 400);
    }

    const deleted = await deleteNativeDomain(user, domainId);
    return json({ success: deleted });
  } catch (error) {
    return apiError(error);
  }
}
