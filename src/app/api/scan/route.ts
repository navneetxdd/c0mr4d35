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
import type { ScanStageEvent } from "@/lib/scan/progress";

export const runtime = "nodejs";
export const maxDuration = 120;

const BodySchema = z.object({
  target: z.string().min(4).max(2048),
  baselineHtml: z.string().max(3_000_000).optional().nullable(),
  baselineBehavior: z
    .object({
      externalScriptOrigins: z.array(z.string()).max(200).optional(),
      formActions: z.array(z.string()).max(200).optional(),
      openPorts: z.array(z.number()).max(200).optional(),
      subdomains: z.array(z.string()).max(500).optional(),
    })
    .optional()
    .nullable(),
  singlePage: z.boolean().optional().default(false),
  withAi: z.boolean().optional().default(true),
  stream: z.boolean().optional().default(true),
});

async function authorizeAdhoc(): Promise<
  | { ok: true; canPersist: boolean; userId: string | null }
  | { ok: false; response: NextResponse }
> {
  if (!process.env.NEXT_PUBLIC_SUPABASE_URL) {
    if (process.env.NODE_ENV === "production") {
      return {
        ok: false,
        response: NextResponse.json({ ok: false, error: "Service unavailable" }, { status: 503 }),
      };
    }
    return { ok: true, canPersist: false, userId: null };
  }

  try {
    const profile = await requireRole("analyst");
    const adhocOk = await checkRateLimit(`scan:adhoc:${profile.id}`, 3, 60);
    const userOk = await checkRateLimit(`scan:user:${profile.id}`, 10, 600);
    if (!adhocOk || !userOk) {
      return {
        ok: false,
        response: NextResponse.json({ ok: false, error: "Rate limit exceeded" }, { status: 429 }),
      };
    }
    return { ok: true, canPersist: Boolean(profile.id), userId: profile.id };
  } catch (e) {
    if (e instanceof UnauthorizedError) {
      return {
        ok: false,
        response: NextResponse.json({ ok: false, error: "Authentication required" }, { status: 401 }),
      };
    }
    if (e instanceof ForbiddenError) {
      return {
        ok: false,
        response: NextResponse.json({ ok: false, error: "Insufficient permissions" }, { status: 403 }),
      };
    }
    throw e;
  }
}

function sseEncode(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

export async function POST(req: NextRequest) {
  const auth = await authorizeAdhoc();
  if (!auth.ok) return auth.response;

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

  const stream = parsed.data.stream !== false;
  if (!stream) {
    try {
      const payload = await executeAdhocScan(parsed.data, auth.canPersist, auth.userId);
      if (!payload.ok) {
        return NextResponse.json({ ok: false, error: payload.error }, { status: 422 });
      }
      return NextResponse.json({ ok: true, scan: payload.scan, verdict: payload.verdict }, { status: 200 });
    } catch {
      return NextResponse.json({ ok: false, error: "Internal scan error" }, { status: 500 });
    }
  }

  const encoder = new TextEncoder();
  const readable = new ReadableStream({
    async start(controller) {
      const send = (event: string, data: unknown) => {
        controller.enqueue(encoder.encode(sseEncode(event, data)));
      };

      try {
        const payload = await executeAdhocScan(parsed.data, auth.canPersist, auth.userId, (stage) => {
          send("stage", stage);
        });
        if (!payload.ok) {
          send("error", { ok: false, error: payload.error });
        } else {
          send("result", { ok: true, scan: payload.scan, verdict: payload.verdict });
        }
      } catch {
        send("error", { ok: false, error: "Internal scan error" });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(readable, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}

async function executeAdhocScan(
  data: z.infer<typeof BodySchema>,
  canPersistAdhoc: boolean,
  userId: string | null,
  onProgress?: (stage: ScanStageEvent) => void,
) {
  const admin = process.env.SUPABASE_SERVICE_ROLE_KEY ? createAdminClient() : null;
  const { loadByokSecrets } = await import("@/lib/auth/byok");
  const secrets = userId
    ? await loadByokSecrets(userId)
    : {
        geminiApiKey: process.env.GEMINI_API_KEY?.trim() || null,
        shodanApiKey: process.env.SHODAN_API_KEY?.trim() || null,
      };

  const explicitBaseline = Boolean(data.baselineHtml || data.baselineBehavior);
  const storedBaseline =
    admin && canPersistAdhoc && userId && !explicitBaseline
      ? await loadAdhocBaseline(admin, data.target, userId)
      : null;

  // #region agent log
  fetch("http://127.0.0.1:7781/ingest/1e3609e4-83e2-4af4-abe1-9c10d5bd2172", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "749116" },
    body: JSON.stringify({
      sessionId: "749116",
      runId: "post-fix",
      hypothesisId: "H-adhoc",
      location: "scan/route.ts:baseline",
      message: "adhoc baseline scope",
      data: {
        hasUserId: Boolean(userId),
        canPersistAdhoc,
        hasStored: Boolean(storedBaseline),
        explicitBaseline,
      },
      timestamp: Date.now(),
    }),
  }).catch(() => {});
  // #endregion

  const storedSignals = (storedBaseline?.signals ?? {}) as {
    externalScriptOrigins?: string[];
    formActions?: string[];
    openPorts?: number[];
    subdomains?: string[];
  };

  const scan = await runScan({
    target: data.target,
    baselineHtml: data.baselineHtml ?? storedBaseline?.html_snapshot ?? null,
    baselineBehavior: data.baselineBehavior ?? storedSignals ?? null,
    singlePage: data.singlePage,
    onProgress,
    shodanApiKey: secrets.shodanApiKey,
  });

  if (!scan.ok) {
    return { ok: false as const, error: scan.error ?? "Scan failed" };
  }

  let evidenceNotes = scan.evidenceNotes ?? [];
  if (admin) {
    await onProgress?.({
      stage: "screenshot_diff",
      pct: 75,
      message: "Capturing screenshot and computing visual evidence",
      artifact: null,
      at: new Date().toISOString(),
    });

    const evidence = await collectScanEvidence({
      admin,
      storageBasePath: `adhoc/${userId ?? "anon"}/${targetKeyFromUrl(data.target)}/${Date.now()}`,
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

    if (!storedBaseline && !explicitBaseline && canPersistAdhoc && userId) {
      await saveAdhocBaseline(admin, data.target, userId, {
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
  } else {
    await onProgress?.({
      stage: "screenshot_diff",
      pct: 75,
      message: "Screenshot persistence unavailable (no service role)",
      artifact: null,
      at: new Date().toISOString(),
    });
  }

  scan.evidenceNotes = evidenceNotes;

  await onProgress?.({
    stage: "persist_ai",
    pct: 98,
    message: data.withAi ? "Requesting AI verdict" : "Skipping AI verdict",
    artifact: null,
    at: new Date().toISOString(),
  });

  const verdict = data.withAi ? await getAiVerdict(scan, secrets.geminiApiKey) : undefined;
  const { html: _html, ...safe } = scan;
  void _html;

  await onProgress?.({
    stage: "done",
    pct: 100,
    message: "Assessment complete",
    artifact: `${safe.findings.length} findings`,
    at: new Date().toISOString(),
  });

  return { ok: true as const, scan: safe, verdict };
}
