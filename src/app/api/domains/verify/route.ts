import { NextRequest } from "next/server";
import { z } from "zod";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { apiError, json, parseJson } from "@/lib/server/api";
import { verifyNativeDomainDns } from "@/lib/server/domains";
import { rateLimit } from "@/lib/server/rate-limit";

export async function POST(req: NextRequest) {
  try {
    const user = await requireUser(req);
    await rateLimit(user.uid, "domains-verify", 15);

    const input = await parseJson(
      req,
      z.object({
        domain: z.string().trim().toLowerCase().min(3).max(253),
        domainId: z.string().optional(),
      })
    );

    const identifier = input.domainId || input.domain;
    const verified = await verifyNativeDomainDns(user, identifier);

    return json({
      success: true,
      domain: verified,
      isVerified: verified.status === "verified",
    });
  } catch (error) {
    return apiError(error);
  }
}
