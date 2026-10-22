import { NextResponse } from "next/server";
import { getMongoDb, isMongoConfigured } from "@/lib/mongodb";

export async function GET() {
  const startTime = Date.now();
  const mongoConfigured = isMongoConfigured();

  if (!mongoConfigured) {
    return NextResponse.json({
      status: "degraded",
      timestamp: new Date().toISOString(),
      mongodb: {
        configured: false,
        status: "disconnected",
        message: "MONGODB_URI is not configured in environment.",
      },
    }, { status: 503 });
  }

  try {
    const db = await getMongoDb();
    const pingResult = await db.command({ ping: 1 });
    const latencyMs = Date.now() - startTime;

    return NextResponse.json({
      status: "ok",
      timestamp: new Date().toISOString(),
      mongodb: {
        configured: true,
        status: "connected",
        databaseName: db.databaseName,
        ping: pingResult,
        latencyMs,
      },
    }, { status: 200 });
  } catch (err: unknown) {
    const latencyMs = Date.now() - startTime;
    const errorMessage = err instanceof Error ? err.message : String(err);

    return NextResponse.json({
      status: "error",
      timestamp: new Date().toISOString(),
      mongodb: {
        configured: true,
        status: "error",
        error: errorMessage,
        latencyMs,
      },
    }, { status: 500 });
  }
}
