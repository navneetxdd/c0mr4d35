import { NextRequest, NextResponse } from "next/server";
import { drainScanJobs, scanDueAssets } from "@/lib/scan/persist";

export const runtime = "nodejs";
export const maxDuration = 300;

export async function POST(req: NextRequest) {
  const secret = process.env.CRON_SECRET;
  if (!secret) {
    return NextResponse.json({ ok: false, error: "Cron not configured" }, { status: 503 });
  }

  const auth = req.headers.get("authorization");
  if (auth !== `Bearer ${secret}`) {
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
