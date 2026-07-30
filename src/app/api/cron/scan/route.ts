import { createHash, timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { drainScanJobs, enqueueDueAssets } from "@/lib/scan/persist";

export const runtime = "nodejs";
/** Hobby cap is 60s; keep headroom so we can still flush a JSON 200. */
export const maxDuration = 60;

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

  const started = Date.now();
  // Leave ~8s to serialize the response before the platform kills the isolate.
  const budgetMs = 50_000;

  try {
    const enqueued = await enqueueDueAssets(10);
    const remaining = budgetMs - (Date.now() - started);
    const jobs = await drainScanJobs(1, {
      budgetMs: Math.max(5_000, remaining),
      cronLite: true,
    });
    return NextResponse.json(
      { ok: true, jobs, enqueued, elapsedMs: Date.now() - started },
      { status: 200 },
    );
  } catch {
    // Auth already passed — return 200 so the GitHub Actions scheduler does not
    // page on every transient DB/scan failure. Next tick retries pending jobs.
    return NextResponse.json(
      { ok: true, jobs: 0, enqueued: 0, degraded: true, elapsedMs: Date.now() - started },
      { status: 200 },
    );
  }
}
