import "server-only";
import { getAiVerdict } from "@/lib/ai/gemini";
import { dispatchDiscordAlert } from "@/lib/alerts/discord";
import { createAdminClient } from "@/lib/supabase/admin";
import { runScan, type ScanResult } from "@/lib/scan";
import {
  aggregatePosture,
  countBySeverity,
  dedupeFindings,
  postureScore,
  type ScanFinding,
} from "@/lib/scan/risk";
import { collectScanEvidence } from "@/lib/scan/evidence";

const HTML_CAP = 500_000;

export interface ExecuteScanOptions {
  assetId: string;
  trigger: "manual" | "cron";
  userId?: string | null;
  /** First scan or explicit re-baseline — stores a new baseline row. */
  establishBaseline?: boolean;
  singlePage?: boolean;
  withAi?: boolean;
}

export interface ExecuteScanResult {
  scanId: string;
  ok: boolean;
  error?: string;
}

function truncateHtml(html: string): string {
  return html.length > HTML_CAP ? html.slice(0, HTML_CAP) : html;
}

function severityForIncident(findings: ScanFinding[]): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" {
  if (findings.some((f) => f.risk === "critical" || f.category === "DEFACEMENT")) return "CRITICAL";
  if (findings.some((f) => f.risk === "high")) return "HIGH";
  if (findings.some((f) => f.risk === "medium")) return "MEDIUM";
  return "LOW";
}

function incidentType(findings: ScanFinding[]): string {
  if (findings.some((f) => f.category === "DEFACEMENT")) return "DEFACEMENT";
  if (findings.some((f) => f.risk === "critical")) return "CRITICAL FINDING";
  return "POSTURE DEGRADED";
}

async function persistFindings(
  admin: ReturnType<typeof createAdminClient>,
  scanId: string,
  assetId: string,
  findings: ScanFinding[],
) {
  if (!findings.length) return;
  const rows = findings.map((f) => ({
    scan_id: scanId,
    asset_id: assetId,
    category: f.category,
    risk: f.risk,
    title: f.title,
    detail: f.detail,
    remediation: f.remediation,
    evidence: f.evidence ?? null,
    reference: f.reference ?? null,
    owasp: f.owasp ?? null,
    cwe: f.cwe ?? null,
    url: f.url ?? null,
  }));
  const { error } = await admin.from("findings").insert(rows);
  if (error) throw new Error(error.message);
}

async function maybeAlert(
  admin: ReturnType<typeof createAdminClient>,
  assetId: string,
  scanId: string,
  assetName: string,
  scan: ScanResult,
) {
  const critical = scan.findings.filter((f) => f.risk === "critical" || f.category === "DEFACEMENT");
  const high = scan.findings.filter((f) => f.risk === "high");
  const notify = critical.length > 0 || high.length > 0 || scan.driftPct >= 8;
  if (!notify) return;

  const top = critical[0] ?? high[0];
  const severity = top?.risk ?? (scan.driftPct >= 25 ? "critical" : "high");
  const message = top
    ? `${assetName}: ${top.title}`
    : `${assetName}: content drift ${scan.driftPct}%`;

  const delivered = await dispatchDiscordAlert(
    `Datum · ${severity.toUpperCase()}`,
    message,
    severity as "critical" | "high",
  );

  await admin.from("alerts").insert({
    asset_id: assetId,
    scan_id: scanId,
    severity,
    message,
    channel: delivered ? "discord" : "in-app",
    delivered,
  });

  const openIncident = critical.length > 0 || scan.driftPct >= 25;
  if (openIncident) {
    const { data: existing } = await admin
      .from("incidents")
      .select("id")
      .eq("asset_id", assetId)
      .eq("status", "open")
      .limit(1);
    if (!existing?.length) {
      await admin.from("incidents").insert({
        asset_id: assetId,
        scan_id: scanId,
        severity: severityForIncident(scan.findings),
        type: incidentType(scan.findings),
        status: "open",
        mttd_sec: Math.round(scan.elapsedMs / 1000),
      });
    }
  }
}

/**
 * Runs the scan engine for a persisted asset and writes scans, findings,
 * baselines, alerts, and incidents via the service-role client.
 */
export async function executeScanForAsset(opts: ExecuteScanOptions): Promise<ExecuteScanResult> {
  const admin = createAdminClient();

  const { data: asset, error: assetErr } = await admin
    .from("assets")
    .select("*")
    .eq("id", opts.assetId)
    .single();
  if (assetErr || !asset) {
    return { scanId: "", ok: false, error: "Asset not found" };
  }

  const { data: baseline } = await admin
    .from("baselines")
    .select("html_snapshot, signals, screenshot_path, favicon_hash")
    .eq("asset_id", opts.assetId)
    .order("established_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  const { data: scanRow, error: scanInsertErr } = await admin
    .from("scans")
    .insert({
      asset_id: opts.assetId,
      status: "scanning",
      trigger: opts.trigger,
      created_by: opts.userId ?? null,
      started_at: new Date().toISOString(),
    })
    .select("id")
    .single();
  if (scanInsertErr || !scanRow) {
    return { scanId: "", ok: false, error: "Could not create scan record" };
  }
  const scanId = scanRow.id as string;

  let scan: ScanResult;
  try {
    scan = await runScan({
      target: asset.url,
      baselineHtml: baseline?.html_snapshot ?? null,
      baselineBehavior: (baseline?.signals as { externalScriptOrigins?: string[] }) ?? null,
      singlePage: opts.singlePage ?? false,
    });
  } catch {
    await admin
      .from("scans")
      .update({ status: "error", error: "Scan engine failure", finished_at: new Date().toISOString() })
      .eq("id", scanId);
    return { scanId, ok: false, error: "Scan engine failure" };
  }

  if (!scan.ok) {
    await admin
      .from("scans")
      .update({
        status: "error",
        error: scan.error ?? "Scan failed",
        finished_at: new Date().toISOString(),
      })
      .eq("id", scanId);
    return { scanId, ok: false, error: scan.error ?? "Scan failed" };
  }

  const evidence = await collectScanEvidence({
    admin,
    storageBasePath: `assets/${opts.assetId}/scans/${scanId}`,
    targetUrl: scan.target,
    html: scan.html,
    baseline: baseline
      ? {
          screenshotPath: baseline.screenshot_path as string | null,
          faviconHash: baseline.favicon_hash as string | null,
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
  scan.baselineState = baseline ? "reused" : "created";
  scan.evidenceNotes = evidence.notes;

  const verdict = opts.withAi !== false ? await getAiVerdict(scan) : null;

  await admin
    .from("scans")
    .update({
      status: "done",
      http_status: scan.httpStatus,
      posture: scan.posture,
      posture_score: scan.postureScore,
      drift_pct: scan.driftPct,
      pages_scanned: scan.pagesScanned,
      tech_stack: scan.techStack,
      severity_counts: scan.severityCounts,
      signals: { ...scan.signals, evidenceNotes: scan.evidenceNotes ?? [] },
      ai_verdict: verdict ?? null,
      dom_hash: scan.domHash,
      screenshot_path: scan.screenshotPath ?? null,
      diff_path: scan.diffPath ?? null,
      visual_drift_pct: scan.visualDriftPct ?? null,
      favicon_hash: scan.faviconHash ?? null,
      favicon_changed: scan.faviconChanged ?? false,
      finished_at: new Date().toISOString(),
    })
    .eq("id", scanId);

  await persistFindings(admin, scanId, opts.assetId, scan.findings);

  const shouldBaseline =
    opts.establishBaseline ||
    !baseline ||
    !baseline.screenshot_path ||
    !baseline.favicon_hash;
  if (shouldBaseline && scan.html) {
    await admin.from("baselines").insert({
      asset_id: opts.assetId,
      dom_hash: scan.domHash,
      signals: scan.signals,
      screenshot_path: scan.screenshotPath ?? null,
      html_snapshot: truncateHtml(scan.html),
      favicon_hash: scan.faviconHash ?? null,
      established_by: opts.userId ?? null,
    });
  }

  await admin
    .from("assets")
    .update({ last_scanned_at: new Date().toISOString() })
    .eq("id", opts.assetId);

  await maybeAlert(admin, opts.assetId, scanId, asset.name, scan);

  return { scanId, ok: true };
}

/** Processes pending scan_jobs rows (leased atomically). */
export async function drainScanJobs(limit = 5): Promise<number> {
  const admin = createAdminClient();

  const { data: jobs } = await admin
    .from("scan_jobs")
    .select("id, asset_id, trigger, requested_by")
    .eq("status", "pending")
    .order("created_at", { ascending: true })
    .limit(limit);

  if (!jobs?.length) return 0;

  let processed = 0;
  for (const job of jobs) {
    const leaseUntil = new Date(Date.now() + 5 * 60_000).toISOString();
    const { data: leased } = await admin
      .from("scan_jobs")
      .update({ status: "leased", lease_until: leaseUntil })
      .eq("id", job.id)
      .eq("status", "pending")
      .select("id")
      .maybeSingle();
    if (!leased) continue;

    const result = await executeScanForAsset({
      assetId: job.asset_id,
      trigger: job.trigger as "manual" | "cron",
      userId: job.requested_by,
      establishBaseline: false,
    });

    await admin
      .from("scan_jobs")
      .update({ status: result.ok ? "done" : "error" })
      .eq("id", job.id);
    processed += 1;
  }
  return processed;
}

/** Cron: scan assets with monitoring_enabled due by interval. */
export async function scanDueAssets(limit = 5): Promise<number> {
  const admin = createAdminClient();
  const { data: assets } = await admin
    .from("assets")
    .select("id, scan_interval_min, last_scanned_at")
    .eq("monitoring_enabled", true)
    .limit(50);

  if (!assets?.length) return 0;

  const due = assets.filter((a) => {
    if (!a.last_scanned_at) return true;
    const elapsed = Date.now() - new Date(a.last_scanned_at).getTime();
    return elapsed >= (a.scan_interval_min ?? 60) * 60_000;
  });

  let processed = 0;
  for (const asset of due.slice(0, limit)) {
    await executeScanForAsset({
      assetId: asset.id,
      trigger: "cron",
      establishBaseline: false,
    });
    processed += 1;
  }
  return processed;
}
