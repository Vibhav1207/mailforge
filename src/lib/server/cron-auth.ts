import { timingSafeEqual } from "node:crypto";
import { NextRequest } from "next/server";
import { ApiError } from "./errors";

export function requireCron(req: NextRequest): void {
  const secret = process.env.CRON_SECRET || "";
  if (secret.length < 32) throw new ApiError(503, "Configure CRON_SECRET with at least 32 random characters.", "CONFIGURATION_REQUIRED");
  const expected = Buffer.from(`Bearer ${secret}`);
  const actual = Buffer.from(req.headers.get("authorization") || "");
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) throw new ApiError(401, "Invalid worker credentials.", "UNAUTHORIZED");
}
