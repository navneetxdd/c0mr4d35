import { createHash, timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { drainScanJobs, scanDueAssets } from "@/lib/scan/persist";

export const runtime = "nodejs";
export const maxDuration = 300;

/** Compare bearer token to secret without leaking length via early return. */
function bearerMatches(header: string | null, secret: string): boolean {
  if (!header || !header.startsWith("Bearer ")) return false;
  const token = header.slice("Bearer ".length);
  const a = createHash("sha256").update(token).digest();
  const b = createHash("sha256").update(secret).digest();
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
