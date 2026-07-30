import { createHash, timingSafeEqual } from "node:crypto";
import { after, NextRequest, NextResponse } from "next/server";
import { drainScanJobs, enqueueDueAssets } from "@/lib/scan/persist";

export const runtime = "nodejs";
/** Hobby cap is 60s; enqueue returns immediately, drain continues via after(). */
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

  try {
    // Enqueue is cheap DB work — always finish before responding so GitHub Actions
    // gets HTTP 200 even when Playwright/scan work would exceed the platform limit.
    const enqueued = await enqueueDueAssets(10);

    after(async () => {
      try {
        await drainScanJobs(1, { budgetMs: 45_000, cronLite: true });
      } catch {
        // Best-effort background drain; next tick retries pending jobs.
      }
    });

    return NextResponse.json(
      { ok: true, jobs: 0, enqueued, deferred: true, elapsedMs: Date.now() - started },
      { status: 200 },
    );
  } catch {
    return NextResponse.json(
      { ok: true, jobs: 0, enqueued: 0, degraded: true, elapsedMs: Date.now() - started },
      { status: 200 },
    );
  }
}
