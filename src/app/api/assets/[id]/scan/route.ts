import { NextRequest, NextResponse } from "next/server";
import {
  ForbiddenError,
  UnauthorizedError,
  requireRole,
} from "@/lib/auth/require";
import { checkRateLimit } from "@/lib/auth/rate-limit";
import { executeScanForAsset } from "@/lib/scan/persist";

export const runtime = "nodejs";
export const maxDuration = 120;

export async function POST(
  _req: NextRequest,
  ctx: { params: Promise<{ id: string }> },
) {
  if (!process.env.NEXT_PUBLIC_SUPABASE_URL) {
    return NextResponse.json({ ok: false, error: "Service unavailable" }, { status: 503 });
  }

  let profile;
  try {
    profile = await requireRole("analyst");
  } catch (e) {
    if (e instanceof UnauthorizedError) {
      return NextResponse.json({ ok: false, error: "Authentication required" }, { status: 401 });
    }
    if (e instanceof ForbiddenError) {
      return NextResponse.json({ ok: false, error: "Insufficient permissions" }, { status: 403 });
    }
    throw e;
  }

  const allowed = await checkRateLimit(`scan:user:${profile.id}`, 10, 600);
  if (!allowed) {
    return NextResponse.json({ ok: false, error: "Rate limit exceeded" }, { status: 429 });
  }

  const { id } = await ctx.params;
  const result = await executeScanForAsset({
    assetId: id,
    trigger: "manual",
    userId: profile.id,
    establishBaseline: false,
  });

  if (!result.ok) {
    return NextResponse.json({ ok: false, error: result.error ?? "Scan failed" }, { status: 422 });
  }
  return NextResponse.json({ ok: true, scanId: result.scanId }, { status: 200 });
}
