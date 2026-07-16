import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { runScan } from "@/lib/scan";
import { getAiVerdict } from "@/lib/ai/gemini";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  ForbiddenError,
  UnauthorizedError,
  requireRole,
} from "@/lib/auth/require";
import { checkRateLimit } from "@/lib/auth/rate-limit";
import { loadAdhocBaseline, saveAdhocBaseline, targetKeyFromUrl } from "@/lib/scan/adhoc";
import { collectScanEvidence } from "@/lib/scan/evidence";
import { aggregatePosture, countBySeverity, dedupeFindings, postureScore } from "@/lib/scan/risk";

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
  let canPersistAdhoc = false;
  if (!process.env.NEXT_PUBLIC_SUPABASE_URL) {
    if (process.env.NODE_ENV === "production") {
      return NextResponse.json({ ok: false, error: "Service unavailable" }, { status: 503 });
    }
  } else {
    try {
      const profile = await requireRole("analyst");
      canPersistAdhoc = Boolean(profile.id);
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
    const admin = process.env.SUPABASE_SERVICE_ROLE_KEY ? createAdminClient() : null;
    const explicitBaseline = Boolean(parsed.data.baselineHtml || parsed.data.baselineBehavior);
    const storedBaseline =
      admin && canPersistAdhoc && !explicitBaseline
        ? await loadAdhocBaseline(admin, parsed.data.target)
        : null;

    const scan = await runScan({
      target: parsed.data.target,
      baselineHtml: parsed.data.baselineHtml ?? storedBaseline?.html_snapshot ?? null,
      baselineBehavior:
        parsed.data.baselineBehavior ??
        ((storedBaseline?.signals as { externalScriptOrigins?: string[]; formActions?: string[] }) ?? null),
      singlePage: parsed.data.singlePage,
    });

    if (!scan.ok) {
      return NextResponse.json({ ok: false, error: scan.error ?? "Scan failed" }, { status: 422 });
    }

    let evidenceNotes = scan.evidenceNotes ?? [];
    if (admin) {
      const evidence = await collectScanEvidence({
        admin,
        storageBasePath: `adhoc/${targetKeyFromUrl(parsed.data.target)}/${Date.now()}`,
        targetUrl: scan.target,
        html: scan.html,
        baseline: storedBaseline
          ? {
              screenshotPath: storedBaseline.screenshot_path,
              faviconHash: storedBaseline.favicon_hash,
            }
          : null,
      });

      const mergedFindings = dedupeFindings([...scan.findings, ...evidence.extraFindings]);
      scan.findings = mergedFindings;
      scan.posture = aggregatePosture(mergedFindings);
      scan.postureScore = postureScore(mergedFindings);
      scan.severityCounts = countBySeverity(mergedFindings);
      scan.visualDriftPct = evidence.visualDriftPct;
      scan.screenshotPath = evidence.screenshotPath;
      scan.baselineScreenshotPath = evidence.baselineScreenshotPath;
      scan.diffPath = evidence.diffPath;
      scan.screenshotUrl = evidence.screenshotUrl;
      scan.baselineScreenshotUrl = evidence.baselineScreenshotUrl;
      scan.diffUrl = evidence.diffUrl;
      scan.faviconHash = evidence.faviconHash;
      scan.faviconChanged = evidence.faviconChanged;
      scan.faviconUrl = evidence.faviconUrl;
      evidenceNotes = [...evidenceNotes, ...evidence.notes];

      if (!storedBaseline && !explicitBaseline && canPersistAdhoc) {
        await saveAdhocBaseline(admin, parsed.data.target, {
          html_snapshot: scan.html,
          signals: scan.signals as unknown as Record<string, unknown>,
          screenshot_path: evidence.screenshotPath,
          favicon_hash: evidence.faviconHash,
        });
        scan.baselineState = "created";
      } else if (explicitBaseline) {
        scan.baselineState = "provided";
      } else if (storedBaseline) {
        scan.baselineState = "reused";
      } else {
        scan.baselineState = "none";
      }
    }

    scan.evidenceNotes = evidenceNotes;

    const verdict = parsed.data.withAi ? await getAiVerdict(scan) : undefined;
    const { html: _html, ...safe } = scan;
    void _html;

    return NextResponse.json({ ok: true, scan: safe, verdict }, { status: 200 });
  } catch {
    return NextResponse.json({ ok: false, error: "Internal scan error" }, { status: 500 });
  }
}
