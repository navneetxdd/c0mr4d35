import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { runScan } from "@/lib/scan";
import { getAiVerdict } from "@/lib/ai/gemini";

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

/**
 * On-demand scan endpoint. Validates input with Zod, runs the SSRF-guarded
 * engine, then enriches with the AI verdict (fail-open). Returns a stable
 * shape and never leaks stack traces — production error output is generic.
 */
export async function POST(req: NextRequest) {
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
      // Validation/fetch failure is a client-visible, non-sensitive condition.
      return NextResponse.json({ ok: false, error: scan.error ?? "Scan failed" }, { status: 422 });
    }

    const verdict = parsed.data.withAi ? await getAiVerdict(scan) : undefined;

    // Strip the raw HTML from the response payload (kept server-side only).
    const { html: _html, ...safe } = scan;
    void _html;

    return NextResponse.json({ ok: true, scan: safe, verdict }, { status: 200 });
  } catch {
    return NextResponse.json({ ok: false, error: "Internal scan error" }, { status: 500 });
  }
}
