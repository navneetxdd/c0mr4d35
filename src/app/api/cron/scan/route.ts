import { timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { drainScanJobs, scanDueAssets } from "@/lib/scan/persist";

export const runtime = "nodejs";
export const maxDuration = 300;

function bearerMatches(header: string | null, secret: string): boolean {
  if (!header || !header.startsWith("Bearer ")) return false;
  const token = header.slice("Bearer ".length);
  const a = Buffer.from(token);
  const b = Buffer.from(secret);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export async function POST(req: NextRequest) {
  const secret = process.env.CRON_SECRET;
  if (!secret) {
    return NextResponse.json({ ok: false, error: "Cron not configured" }, { status: 503 });
  }

  if (!bearerMatches(req.headers.get("authorization"), secret)) {
    return NextResponse.json({ ok: false, error: "Unauthorized" }, { status: 401 });
  }

  try {
    const jobs = await drainScanJobs(5);
    const scheduled = await scanDueAssets(5);
    return NextResponse.json({ ok: true, jobs, scheduled }, { status: 200 });
  } catch {
    return NextResponse.json({ ok: false, error: "Cron execution failed" }, { status: 500 });
  }
}
