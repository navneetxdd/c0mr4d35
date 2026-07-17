import "server-only";
import { hasRole } from "@/lib/auth/rbac";
import { createAdminClient } from "@/lib/supabase/admin";
import { createServerSupabase } from "@/lib/supabase/server";
import type {
  Asset as DbAsset,
  Baseline,
  Scan,
  Finding,
  AuditEntry as DbAuditEntry,
  Profile,
} from "@/lib/supabase/types";
import type {
  Asset,
  AuditEntry,
  FeedEvent,
  Incident,
  Member,
  Posture,
  ScanEntry,
  Telemetry,
  VisualEvidence,
} from "@/lib/types";
import type { AiVerdict } from "@/lib/ai/gemini";
import { mapFindingRow } from "@/lib/data/findings";
import { createEvidenceSignedUrl } from "@/lib/scan/evidence-storage";

import type { ShellContext } from "@/lib/data/shell";
export type { ShellContext } from "@/lib/data/shell";

function hostFromUrl(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function mapPosture(p: string | null | undefined): Asset["posture"] {
  if (p === "critical" || p === "watch" || p === "secure" || p === "scanning") return p;
  return "secure";
}

/**
 * Datum degrades gracefully when Supabase isn't configured (local dev, or a
 * misconfigured deploy) instead of throwing a 500. Reads return safe empty
 * defaults. Production always has Supabase set, so this path never runs there;
 * middleware still fails closed in production regardless.
 */
function supabaseConfigured(): boolean {
  return Boolean(process.env.NEXT_PUBLIC_SUPABASE_URL && process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);
}
/** Only outside production may an unconfigured instance expose the console for local dev. */
const DEV_UNAUTH = process.env.NODE_ENV !== "production";
const EMPTY_TELEMETRY: Telemetry = {
  assets: 0,
  scans24h: 0,
  openIncidents: 0,
  mttdSec: null,
  scanSuccessPct: null,
};

export function mapAssetRow(
  asset: DbAsset,
  latest: Scan | null,
  driftHistory: number[],
  openIncident: boolean,
  thumbnail = "",
  baselineCapture = "",
  currentCapture = "",
  diffCapture = "",
): Asset {
  const scanning = latest?.status === "scanning" || latest?.status === "queued";
  return {
    id: asset.id,
    name: asset.name,
    host: hostFromUrl(asset.url),
    posture: scanning ? "scanning" : mapPosture(latest?.posture),
    driftScore: Number(latest?.drift_pct ?? 0),
    driftHistory,
    lastCheckAt: latest?.finished_at ?? latest?.started_at ?? asset.created_at,
    thumbnail,
    baselineCapture,
    currentCapture,
    diffCapture,
    openIncident,
    scanIntervalMin: asset.scan_interval_min,
  };
}

export async function fetchAssetsWithScans(): Promise<Asset[]> {
  if (!supabaseConfigured()) return [];
  const supabase = await createServerSupabase();
  const admin = createAdminClient();
  const { data: assets } = await supabase.from("assets").select("*").order("created_at", { ascending: false });
  if (!assets?.length) return [];

  const ids = assets.map((a) => a.id);
  const { data: scans } = await supabase
    .from("scans")
    .select("*")
    .in("asset_id", ids)
    .order("started_at", { ascending: false });

  const { data: incidents } = await supabase
    .from("incidents")
    .select("asset_id")
    .in("asset_id", ids)
    .eq("status", "open");
  const { data: baselines } = await supabase
    .from("baselines")
    .select("asset_id, screenshot_path")
    .in("asset_id", ids)
    .order("established_at", { ascending: false });

  const openSet = new Set((incidents ?? []).map((i) => i.asset_id));
  const latestByAsset = new Map<string, Scan>();
  const historyByAsset = new Map<string, number[]>();
  const baselineByAsset = new Map<string, Baseline>();

  for (const s of scans ?? []) {
    if (!latestByAsset.has(s.asset_id)) latestByAsset.set(s.asset_id, s as Scan);
    const hist = historyByAsset.get(s.asset_id) ?? [];
    if (hist.length < 7 && s.drift_pct != null) hist.push(Number(s.drift_pct));
    historyByAsset.set(s.asset_id, hist);
  }
  for (const b of baselines ?? []) {
    if (!baselineByAsset.has(b.asset_id)) baselineByAsset.set(b.asset_id, b as Baseline);
  }

  const urlCache = new Map<string, string | null>();
  async function signed(path: string | null | undefined) {
    if (!path) return "";
    if (!urlCache.has(path)) {
      urlCache.set(path, await createEvidenceSignedUrl(admin, path));
    }
    return urlCache.get(path) ?? "";
  }

  return Promise.all(
    (assets as DbAsset[]).map(async (a) => {
      const latest = latestByAsset.get(a.id) ?? null;
      const baseline = baselineByAsset.get(a.id) ?? null;
      const currentCapture = await signed(latest?.screenshot_path);
      const baselineCapture = await signed(baseline?.screenshot_path);
      const diffCapture = await signed(latest?.diff_path);
      return mapAssetRow(
        a,
        latest,
        historyByAsset.get(a.id) ?? [],
        openSet.has(a.id),
        currentCapture || baselineCapture,
        baselineCapture,
        currentCapture,
        diffCapture,
      );
    }),
  );
}

export async function fetchTelemetry(): Promise<Telemetry> {
  if (!supabaseConfigured()) return EMPTY_TELEMETRY;
  const supabase = await createServerSupabase();
  const since = new Date(Date.now() - 86_400_000).toISOString();

  const [
    { count: assetCount },
    { count: scans24 },
    { count: openIncidents },
    { count: scansOk24 },
    { data: mttdRows },
  ] = await Promise.all([
    supabase.from("assets").select("*", { count: "exact", head: true }),
    supabase.from("scans").select("*", { count: "exact", head: true }).gte("started_at", since),
    supabase.from("incidents").select("*", { count: "exact", head: true }).eq("status", "open"),
    supabase
      .from("scans")
      .select("*", { count: "exact", head: true })
      .gte("started_at", since)
      .eq("status", "done"),
    supabase.from("incidents").select("mttd_sec").not("mttd_sec", "is", null).gt("mttd_sec", 0).limit(100),
  ]);

  const mttdSamples = (mttdRows ?? [])
    .map((r) => (typeof r.mttd_sec === "number" ? r.mttd_sec : null))
    .filter((n): n is number => n != null && n > 0);
  const mttdSec =
    mttdSamples.length > 0
      ? Math.round(mttdSamples.reduce((a, b) => a + b, 0) / mttdSamples.length)
      : null;

  const total = scans24 ?? 0;
  const ok = scansOk24 ?? 0;
  const scanSuccessPct = total === 0 ? null : Math.round((ok / total) * 1000) / 10;

  return {
    assets: assetCount ?? 0,
    scans24h: total,
    openIncidents: openIncidents ?? 0,
    mttdSec,
    scanSuccessPct,
  };
}

export async function fetchFeedEvents(limit = 40): Promise<FeedEvent[]> {
  if (!supabaseConfigured()) return [];
  const supabase = await createServerSupabase();
  const events: FeedEvent[] = [];

  const [{ data: scans }, { data: alerts }, { data: findings }] = await Promise.all([
    supabase.from("scans").select("id, asset_id, posture, status, started_at, finished_at").order("started_at", { ascending: false }).limit(15),
    supabase.from("alerts").select("id, severity, message, created_at").order("created_at", { ascending: false }).limit(15),
    supabase.from("findings").select("id, category, risk, title, created_at, asset_id").order("created_at", { ascending: false }).limit(15),
  ]);

  for (const s of scans ?? []) {
    const posture = s.status === "scanning" ? "scanning" : mapPosture(s.posture);
    events.push({
      id: `scan-${s.id}`,
      at: s.finished_at ?? s.started_at,
      posture,
      message: `SCAN ${s.status?.toUpperCase()} · asset ${s.asset_id.slice(0, 8)}`,
    });
  }
  for (const a of alerts ?? []) {
    events.push({
      id: `alert-${a.id}`,
      at: a.created_at,
      posture: a.severity === "critical" ? "critical" : "watch",
      message: `ALERT · ${a.message}`,
    });
  }
  for (const f of findings ?? []) {
    if (f.category !== "DEFACEMENT" && f.risk !== "critical" && f.risk !== "high") continue;
    events.push({
      id: `finding-${f.id}`,
      at: f.created_at,
      posture: f.risk === "critical" ? "critical" : "watch",
      message: `${f.category} · ${f.title}`,
    });
  }

  return events
    .sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime())
    .slice(0, limit);
}

export interface AssetDetailData {
  asset: DbAsset;
  assetView: Asset;
  scans: ScanEntry[];
  findings: import("@/lib/types").Finding[];
  evidence: VisualEvidence;
  aiVerdict: AiVerdict | null;
}

export async function fetchAssetDetail(id: string): Promise<AssetDetailData | null> {
  if (!supabaseConfigured()) return null;
  const supabase = await createServerSupabase();
  const admin = createAdminClient();
  const { data: asset } = await supabase.from("assets").select("*").eq("id", id).single();
  if (!asset) return null;

  const [{ data: scans }, { data: findings }, { data: baseline }, { data: openInc }] = await Promise.all([
    supabase.from("scans").select("*").eq("asset_id", id).order("started_at", { ascending: false }).limit(30),
    supabase
      .from("findings")
      .select("*")
      .eq("asset_id", id)
      .order("created_at", { ascending: false })
      .limit(50),
    supabase
      .from("baselines")
      .select("html_snapshot,screenshot_path,favicon_hash")
      .eq("asset_id", id)
      .order("established_at", { ascending: false })
      .limit(1)
      .maybeSingle(),
    supabase.from("incidents").select("id").eq("asset_id", id).eq("status", "open").limit(1),
  ]);

  const scanList = (scans ?? []) as Scan[];
  const latest = scanList[0] ?? null;
  const driftHistory = scanList
    .slice(0, 7)
    .map((s) => Number(s.drift_pct ?? 0))
    .reverse();

  const assetView = mapAssetRow(asset as DbAsset, latest, driftHistory, Boolean(openInc?.length));

  const scanEntries: ScanEntry[] = scanList.map((s) => ({
    id: s.id,
    at: s.finished_at ?? s.started_at,
    driftPct: Number(s.drift_pct ?? 0),
    visualDriftPct: Number(s.visual_drift_pct ?? 0),
    posture: mapPosture(s.posture),
    trigger: s.trigger === "cron" ? "CRON" : "MANUAL",
    durationMs: s.finished_at
      ? new Date(s.finished_at).getTime() - new Date(s.started_at).getTime()
      : 0,
    status: s.status === "error" ? "failed" : s.status === "scanning" ? "scanning" : s.status === "done" ? "done" : "queued",
  }));

  const latestScanId = latest?.id;
  const latestFindings = (findings ?? [])
    .filter((f) => f.scan_id === latestScanId)
    .map((f) => mapFindingRow(f as Finding));

  const [baselineCapture, currentCapture, diffCapture] = await Promise.all([
    createEvidenceSignedUrl(admin, (baseline as Baseline | null)?.screenshot_path ?? null),
    createEvidenceSignedUrl(admin, latest?.screenshot_path ?? null),
    createEvidenceSignedUrl(admin, latest?.diff_path ?? null),
  ]);

  assetView.thumbnail = currentCapture || baselineCapture || "";
  assetView.baselineCapture = baselineCapture ?? "";
  assetView.currentCapture = currentCapture ?? "";
  assetView.diffCapture = diffCapture ?? "";

  return {
    asset: asset as DbAsset,
    assetView,
    scans: scanEntries,
    findings: latestFindings,
    evidence: {
      baselineState: baseline ? "reused" : "none",
      domDriftPct: Number(latest?.drift_pct ?? 0),
      visualDriftPct: latest?.visual_drift_pct ?? null,
      baselineHtml: (baseline as Baseline | null)?.html_snapshot ?? null,
      baselineCapture: baselineCapture ?? null,
      currentCapture: currentCapture ?? null,
      diffCapture: diffCapture ?? null,
      faviconHash: (latest?.favicon_hash as string | null) ?? ((baseline as Baseline | null)?.favicon_hash ?? null),
      faviconChanged: Boolean(latest?.favicon_changed),
      faviconUrl: null,
      notes: Array.isArray((latest?.signals as { evidenceNotes?: string[] } | null)?.evidenceNotes)
        ? (((latest?.signals as { evidenceNotes?: string[] }).evidenceNotes) ?? [])
        : [],
      ports: Array.isArray((latest as { ports_json?: unknown } | null)?.ports_json)
        ? (((latest as { ports_json: VisualEvidence["ports"] }).ports_json) ?? [])
        : [],
      subdomains: Array.isArray((latest as { subdomains_json?: unknown } | null)?.subdomains_json)
        ? (((latest as { subdomains_json: VisualEvidence["subdomains"] }).subdomains_json) ?? [])
        : [],
      scripts: Array.isArray((latest?.signals as { scripts?: unknown } | null)?.scripts)
        ? (((latest?.signals as { scripts: VisualEvidence["scripts"] }).scripts) ?? [])
        : [],
      egress: Array.isArray((latest?.signals as { egress?: unknown } | null)?.egress)
        ? (((latest?.signals as { egress: VisualEvidence["egress"] }).egress) ?? [])
        : [],
    },
    aiVerdict: (latest?.ai_verdict as AiVerdict | null) ?? null,
  };
}

export async function fetchIncidents(): Promise<Incident[]> {
  if (!supabaseConfigured()) return [];
  const supabase = await createServerSupabase();
  const { data } = await supabase
    .from("incidents")
    .select("*, assets(name)")
    .order("detected_at", { ascending: false });
  if (!data) return [];

  return data.map((row) => {
    const assets = row.assets as { name: string } | null;
    return {
      id: row.id,
      severity: row.severity as Incident["severity"],
      assetId: row.asset_id,
      assetName: assets?.name ?? row.asset_id,
      type: row.type,
      detectedAt: row.detected_at,
      status: row.status as Incident["status"],
      mttdSec: row.mttd_sec ?? 0,
      assignee: row.assignee,
    };
  });
}

export async function fetchMembers(): Promise<Member[]> {
  if (!supabaseConfigured()) return [];
  const supabase = await createServerSupabase();
  const { data } = await supabase.from("profiles").select("*").order("created_at", { ascending: true });
  return (data ?? []).map((p) => ({
    id: p.id,
    email: p.email ?? "",
    role: p.role,
    joinedAt: p.created_at,
  }));
}

export async function fetchCurrentProfile(): Promise<Profile | null> {
  if (!supabaseConfigured()) return null;
  const supabase = await createServerSupabase();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return null;
  const { data } = await supabase.from("profiles").select("*").eq("id", user.id).single();
  return data as Profile | null;
}

export async function fetchAuditLog(): Promise<AuditEntry[]> {
  if (!supabaseConfigured()) return [];
  const supabase = await createServerSupabase();
  const { data } = await supabase.from("audit_log").select("*").order("seq", { ascending: false }).limit(100);
  const rows = (data ?? []) as DbAuditEntry[];
  return rows.map((row) => {
    const target = row.target_table
      ? `${row.target_table}${row.target_id ? `:${row.target_id.slice(0, 8)}` : ""}`
      : "—";
    return {
      seq: row.seq,
      at: row.created_at,
      actor: row.actor ?? "system",
      action: row.action,
      target,
      prevHash: row.prev_hash ?? "—",
      thisHash: row.this_hash,
    };
  });
}

export function globalPostureFromAssets(assets: Asset[]): Posture {
  if (assets.some((a) => a.posture === "critical")) return "critical";
  if (assets.some((a) => a.posture === "watch")) return "watch";
  if (assets.some((a) => a.posture === "scanning")) return "scanning";
  return "secure";
}

export async function fetchShellContext(): Promise<ShellContext> {
  if (!supabaseConfigured()) {
    return {
      posture: "secure",
      watchCount: 0,
      telemetry: EMPTY_TELEMETRY,
      profile: null,
      // Local dev without Supabase can drive the console; a real deploy always
      // has Supabase set, and middleware fails closed in production regardless.
      isAdmin: DEV_UNAUTH,
      isAnalyst: DEV_UNAUTH,
    };
  }
  const [assets, telemetry, profile] = await Promise.all([
    fetchAssetsWithScans(),
    fetchTelemetry(),
    fetchCurrentProfile(),
  ]);
  return {
    posture: globalPostureFromAssets(assets),
    watchCount: assets.filter((a) => a.posture === "watch" || a.posture === "critical").length,
    telemetry,
    profile: profile ? { email: profile.email ?? "", role: profile.role } : null,
    isAdmin: profile?.role === "admin",
    isAnalyst: hasRole(profile?.role, "analyst"),
  };
}
