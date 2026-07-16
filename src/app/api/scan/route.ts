import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { runScan } from "@/lib/scan";
import { getAiVerdict } from "@/lib/ai/gemini";
import {
  ForbiddenError,
  UnauthorizedError,
  requireRole,
} from "@/lib/auth/require";
import { checkRateLimit } from "@/lib/auth/rate-limit";

export const runtime = "nodejs";
export const maxDuration = 60;

const BodySchema = z.object({
  target: z.string().min(4).max(2048),
  baselineHtml: z.string().max(3_000_000).optional().nullable(),
  baselineBehavior: z
    .object({
      externalScriptOrigins: z.array(z.string()).max(200).optional(),
      formActions: z.array(z.string()).max(200).optional(),
    })
    .optional()
    .nullable(),
  singlePage: z.boolean().optional().default(false),
  withAi: z.boolean().optional().default(true),
});

export async function POST(req: NextRequest) {
  if (!process.env.NEXT_PUBLIC_SUPABASE_URL) {
    if (process.env.NODE_ENV === "production") {
      return NextResponse.json({ ok: false, error: "Service unavailable" }, { status: 503 });
    }
  } else {
    try {
      const profile = await requireRole("analyst");
      const adhocOk = await checkRateLimit(`scan:adhoc:${profile.id}`, 3, 60);
      const userOk = await checkRateLimit(`scan:user:${profile.id}`, 10, 600);
      if (!adhocOk || !userOk) {
        return NextResponse.json({ ok: false, error: "Rate limit exceeded" }, { status: 429 });
      }
    } catch (e) {
      if (e instanceof UnauthorizedError) {
        return NextResponse.json({ ok: false, error: "Authentication required" }, { status: 401 });
      }
      if (e instanceof ForbiddenError) {
        return NextResponse.json({ ok: false, error: "Insufficient permissions" }, { status: 403 });
      }
      throw e;
    }
  }

  let json: unknown;
  try {
    json = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid JSON body" }, { status: 400 });
  }

  const parsed = BodySchema.safeParse(json);
  if (!parsed.success) {
    return NextResponse.json(
      { ok: false, error: "Invalid request", issues: parsed.error.flatten().fieldErrors },
      { status: 400 },
    );
  }

  try {
    const scan = await runScan({
      target: parsed.data.target,
      baselineHtml: parsed.data.baselineHtml ?? null,
      baselineBehavior: parsed.data.baselineBehavior ?? null,
      singlePage: parsed.data.singlePage,
    });

    if (!scan.ok) {
      return NextResponse.json({ ok: false, error: scan.error ?? "Scan failed" }, { status: 422 });
    }

    const verdict = parsed.data.withAi ? await getAiVerdict(scan) : undefined;
    const { html: _html, ...safe } = scan;
    void _html;

    return NextResponse.json({ ok: true, scan: safe, verdict }, { status: 200 });
  } catch {
    return NextResponse.json({ ok: false, error: "Internal scan error" }, { status: 500 });
  }
}
