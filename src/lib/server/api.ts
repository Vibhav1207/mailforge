import { NextRequest, NextResponse } from "next/server";
import { z, ZodError } from "zod";
import { ApiError } from "./errors";

export async function readBody(req: NextRequest, maxBytes = 1024 * 1024): Promise<Uint8Array> {
  if (Number(req.headers.get("content-length")) > maxBytes) throw new ApiError(413, "Request body is too large.", "PAYLOAD_TOO_LARGE");
  if (!req.body) return new Uint8Array();
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > maxBytes) {
        await reader.cancel();
        throw new ApiError(413, "Request body is too large.", "PAYLOAD_TOO_LARGE");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks);
}

export async function parseJson<T extends z.ZodTypeAny>(req: NextRequest, schema: T, maxBytes?: number): Promise<z.infer<T>> {
  if (!req.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    throw new ApiError(415, "Content-Type must be application/json.", "UNSUPPORTED_MEDIA_TYPE");
  }
  const raw = await readBody(req, maxBytes);
  let value: unknown;
  try { value = JSON.parse(Buffer.from(raw).toString("utf8")); }
  catch { throw new ApiError(400, "Request body must be valid JSON.", "INVALID_JSON"); }
  return schema.parse(value);
}

export function apiError(error: unknown): NextResponse {
  if (error instanceof ZodError) {
    return NextResponse.json({ error: "Invalid request data.", code: "VALIDATION_ERROR", issues: error.issues.map(({ path, message }) => ({ path: path.join("."), message })) }, { status: 400 });
  }
  if (error instanceof ApiError) {
    return NextResponse.json({ error: error.message, code: error.code }, { status: error.status, headers: error.status === 429 ? { "Retry-After": "60" } : undefined });
  }
  // Database and SMTP errors can contain credentials or recipient data.
  console.error("Backend operation failed", { name: error instanceof Error ? error.name : "UnknownError", code: (error as { code?: string })?.code });
  return NextResponse.json({ error: "The operation could not be completed. Check the backend configuration and try again.", code: "SERVICE_UNAVAILABLE" }, { status: 503 });
}

export function json(data: unknown, status = 200): NextResponse {
  return NextResponse.json(data, { status, headers: { "Cache-Control": "no-store" } });
}
