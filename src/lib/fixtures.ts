import type {
  AiVerdict,
  Asset,
  AuditEntry,
  ChangeRegion,
  FeedEvent,
  Finding,
  Incident,
  Member,
  ScanEntry,
  Telemetry,
} from "./types";

/** Fixed epoch so SSR and client hydrate with identical fixture strings. */
export const FIXTURE_NOW = Date.parse("2026-07-16T05:00:00.000Z");

export const BUILD_HASH = "d7a2c91";

export const telemetry: Telemetry = {
  assets: 7,
  scans24h: 214,
  openIncidents: 2,
  mttdSec: 41,
  uptimePct: 99.9,
};

export const currentUser = {
  email: "navne@ops.datum",
  role: "admin" as const,
};

function ago(ms: number): string {
  return new Date(FIXTURE_NOW - ms).toISOString();
}

export const assets: Asset[] = [
  {
    id: "a1",
    name: "marketing-site-prod",
    host: "www.acme-ops.io",
    posture: "critical",
    driftScore: 38.4,
    driftHistory: [2, 3, 2, 4, 3, 5, 8, 12, 18, 24, 31, 38.4],
    lastCheckAt: ago(42_000),
    thumbnail: "/captures/marketing-current.svg",
    baselineCapture: "/captures/marketing-baseline.svg",
    currentCapture: "/captures/marketing-current.svg",
    openIncident: true,
    scanIntervalMin: 15,
  },
  {
    id: "a2",
    name: "status-page",
    host: "status.acme-ops.io",
    posture: "watch",
    driftScore: 9.2,
    driftHistory: [1, 1, 2, 1, 3, 2, 4, 5, 6, 7, 8, 9.2],
    lastCheckAt: ago(180_000),
    thumbnail: "/captures/status-current.svg",
    baselineCapture: "/captures/status-baseline.svg",
    currentCapture: "/captures/status-current.svg",
    openIncident: true,
    scanIntervalMin: 30,
  },
  {
    id: "a3",
    name: "api-gateway",
    host: "api.acme-ops.io",
    posture: "secure",
    driftScore: 0.4,
    driftHistory: [0.5, 0.3, 0.4, 0.6, 0.2, 0.3, 0.5, 0.4, 0.3, 0.4, 0.5, 0.4],
    lastCheckAt: ago(95_000),
    thumbnail: "/captures/api-current.svg",
    baselineCapture: "/captures/api-baseline.svg",
    currentCapture: "/captures/api-current.svg",
    openIncident: false,
    scanIntervalMin: 15,
  },
  {
    id: "a4",
    name: "docs-portal",
    host: "docs.acme-ops.io",
    posture: "scanning",
    driftScore: 1.1,
    driftHistory: [1, 1.2, 0.9, 1.1, 1.0, 1.3, 1.1, 0.8, 1.0, 1.2, 1.1, 1.1],
    lastCheckAt: ago(12_000),
    thumbnail: "/captures/docs-current.svg",
    baselineCapture: "/captures/docs-baseline.svg",
    currentCapture: "/captures/docs-current.svg",
    openIncident: false,
    scanIntervalMin: 60,
  },
  {
    id: "a5",
    name: "billing-console",
    host: "billing.acme-ops.io",
    posture: "secure",
    driftScore: 0.2,
    driftHistory: [0.2, 0.1, 0.3, 0.2, 0.2, 0.1, 0.2, 0.3, 0.2, 0.1, 0.2, 0.2],
    lastCheckAt: ago(240_000),
    thumbnail: "/captures/billing-current.svg",
    baselineCapture: "/captures/billing-baseline.svg",
    currentCapture: "/captures/billing-current.svg",
    openIncident: false,
    scanIntervalMin: 30,
  },
  {
    id: "a6",
    name: "help-center",
    host: "help.acme-ops.io",
    posture: "secure",
    driftScore: 0.8,
    driftHistory: [0.6, 0.7, 0.9, 0.8, 0.7, 0.8, 0.9, 0.8, 0.7, 0.8, 0.9, 0.8],
    lastCheckAt: ago(310_000),
    thumbnail: "/captures/help-current.svg",
    baselineCapture: "/captures/help-baseline.svg",
    currentCapture: "/captures/help-current.svg",
    openIncident: false,
    scanIntervalMin: 60,
  },
  {
    id: "a7",
    name: "login-edge",
    host: "auth.acme-ops.io",
    posture: "secure",
    driftScore: 0.1,
    driftHistory: [0.1, 0.1, 0.2, 0.1, 0.1, 0.1, 0.2, 0.1, 0.1, 0.1, 0.1, 0.1],
    lastCheckAt: ago(70_000),
    thumbnail: "/captures/auth-current.svg",
    baselineCapture: "/captures/auth-baseline.svg",
    currentCapture: "/captures/auth-current.svg",
    openIncident: false,
    scanIntervalMin: 15,
  },
];

export const feedEvents: FeedEvent[] = [
  {
    id: "e1",
    at: ago(8_000),
    posture: "critical",
    message: "DEFACEMENT · marketing-site-prod · drift 38.4% · Δ regions 03",
  },
  {
    id: "e2",
    at: ago(22_000),
    posture: "scanning",
    message: "SCAN QUEUED · docs-portal · trigger MANUAL · job j_9f2c",
  },
  {
    id: "e3",
    at: ago(61_000),
    posture: "watch",
    message: "DRIFT · status-page · header CSP missing · MEDIUM",
  },
  {
    id: "e4",
    at: ago(118_000),
    posture: "secure",
    message: "BASELINE HELD · api-gateway · drift 0.4% · 1.8s",
  },
  {
    id: "e5",
    at: ago(205_000),
    posture: "scanning",
    message: "CRON LEASE · 04 jobs claimed · worker wrk-render-01",
  },
  {
    id: "e6",
    at: ago(340_000),
    posture: "secure",
    message: "BASELINE HELD · login-edge · drift 0.1% · 1.2s",
  },
  {
    id: "e7",
    at: ago(520_000),
    posture: "watch",
    message: "ALERT DISPATCH · Discord · incident i_status_01",
  },
  {
    id: "e8",
    at: ago(780_000),
    posture: "secure",
    message: "RE-BASELINE · billing-console · actor navne@ops.datum",
  },
];

export const scanHistory: Record<string, ScanEntry[]> = {
  a1: [
    {
      id: "s1",
      at: ago(42_000),
      driftPct: 38.4,
      posture: "critical",
      trigger: "CRON",
      durationMs: 4200,
      status: "done",
    },
    {
      id: "s2",
      at: ago(920_000),
      driftPct: 24.1,
      posture: "watch",
      trigger: "CRON",
      durationMs: 3900,
      status: "done",
    },
    {
      id: "s3",
      at: ago(1_820_000),
      driftPct: 8.2,
      posture: "watch",
      trigger: "MANUAL",
      durationMs: 4100,
      status: "done",
    },
    {
      id: "s4",
      at: ago(2_720_000),
      driftPct: 1.4,
      posture: "secure",
      trigger: "CRON",
      durationMs: 3600,
      status: "done",
    },
    {
      id: "s5",
      at: ago(3_620_000),
      driftPct: 0.6,
      posture: "secure",
      trigger: "CRON",
      durationMs: 3500,
      status: "done",
    },
  ],
};

export const changeRegions: ChangeRegion[] = [
  { id: "Δ01", label: "Hero banner replaced", x: 8, y: 18, w: 84, h: 22 },
  { id: "Δ02", label: "CTA href rewritten", x: 12, y: 46, w: 28, h: 8 },
  { id: "Δ03", label: "Injected script block", x: 62, y: 72, w: 30, h: 14 },
];

export const aiVerdict: AiVerdict = {
  verdict: "DEFACEMENT",
  confidence: 0.94,
  summary:
    "Hero and primary CTA diverge from the established datum; injected third-party script pattern matches known skimmer fingerprints.",
  indicators: [
    { label: "Favicon MMH3 unchanged — identity held", posture: "secure" },
    { label: "DOM canonical hash delta 38.4%", posture: "critical" },
    { label: "pixelmatch regions 03 above threshold", posture: "critical" },
    { label: "Outbound script host not on allowlist", posture: "critical" },
  ],
};

export const findings: Finding[] = [
  {
    id: "f0",
    group: "DEFACEMENT",
    severity: "CRITICAL",
    title: "Major content deviation from baseline",
    detail: "Normalized content drift is 38.4% against the established baseline capture.",
    remediation: "Compare current vs baseline; if unauthorized, restore and investigate the intrusion vector.",
  },
  {
    id: "f1",
    group: "HEADERS",
    severity: "HIGH",
    title: "Content-Security-Policy missing",
    detail: "No CSP header on document response.",
    remediation: "Emit a restrictive CSP; start report-only, then enforce.",
  },
  {
    id: "f2",
    group: "HEADERS",
    severity: "MEDIUM",
    title: "Strict-Transport-Security missing",
    detail: "HSTS not present on apex response.",
    remediation: "Add HSTS with includeSubDomains; preload when ready.",
  },
  {
    id: "f3",
    group: "TLS",
    severity: "MEDIUM",
    title: "Certificate expires in 12 days",
    detail: "Leaf cert is inside the 14-day renewal window.",
    remediation: "Renew before expiry to avoid an outage.",
  },
  {
    id: "f4",
    group: "EXPOSED PATHS",
    severity: "CRITICAL",
    title: "/.git/HEAD reachable",
    detail: "HTTP 200 on /.git/HEAD — repository metadata exposed.",
    remediation: "Block VCS paths at the edge; rotate any leaked secrets.",
  },
  {
    id: "f5",
    group: "CVE",
    severity: "MEDIUM",
    title: "Next.js stack-family advisory",
    detail: "Detected stack family: Next.js. Matched advisory class via OSV.dev.",
    remediation: "Confirm the deployed Next.js version and upgrade past the advisory.",
    cveId: "GHSA-7m8w-4x3x-xxxx",
    stackFamily: "Next.js",
  },
];

export const incidents: Incident[] = [
  {
    id: "i1",
    severity: "CRITICAL",
    assetId: "a1",
    assetName: "marketing-site-prod",
    type: "DEFACEMENT",
    detectedAt: ago(42_000),
    status: "open",
    mttdSec: 38,
    assignee: null,
  },
  {
    id: "i2",
    severity: "MEDIUM",
    assetId: "a2",
    assetName: "status-page",
    type: "HEADER DRIFT",
    detectedAt: ago(61_000),
    status: "acknowledged",
    mttdSec: 52,
    assignee: "navne@ops.datum",
  },
  {
    id: "i3",
    severity: "LOW",
    assetId: "a5",
    assetName: "billing-console",
    type: "TLS EXPIRY WATCH",
    detectedAt: ago(86_400_000),
    status: "resolved",
    mttdSec: 120,
    assignee: "navne@ops.datum",
  },
];

function hashSeq(n: number): string {
  const raw = `datum-audit-${n}-chain`;
  let h = 0;
  for (let i = 0; i < raw.length; i += 1) h = (h * 31 + raw.charCodeAt(i)) >>> 0;
  return h.toString(16).padStart(8, "0") + (n * 7919).toString(16).padStart(8, "0");
}

export const auditLog: AuditEntry[] = Array.from({ length: 24 }, (_, i) => {
  const seq = 1181 + i;
  const prev = i === 0 ? "0000000000000000" : hashSeq(seq - 1);
  const thisHash = hashSeq(seq);
  const actions = [
    ["scan.enqueue", "marketing-site-prod"],
    ["scan.complete", "api-gateway"],
    ["incident.open", "i1"],
    ["role.change", "viewer→admin"],
    ["asset.create", "help-center"],
    ["rebaseline", "billing-console"],
  ] as const;
  const [action, target] = actions[i % actions.length];
  return {
    seq,
    at: ago((24 - i) * 3600_000),
    actor: i % 5 === 0 ? "system:cron" : "navne@ops.datum",
    action,
    target,
    prevHash: prev,
    thisHash,
  };
});

export const members: Member[] = [
  {
    id: "m1",
    email: "navne@ops.datum",
    role: "admin",
    joinedAt: "2026-03-12T09:00:00Z",
  },
  {
    id: "m2",
    email: "priya@ops.datum",
    role: "admin",
    joinedAt: "2026-04-02T14:20:00Z",
  },
  {
    id: "m3",
    email: "jordan@ops.datum",
    role: "viewer",
    joinedAt: "2026-05-18T11:05:00Z",
  },
  {
    id: "m4",
    email: "alex@ops.datum",
    role: "viewer",
    joinedAt: "2026-06-01T08:40:00Z",
  },
];

export function globalPosture(list: Asset[]): "secure" | "watch" | "critical" {
  if (list.some((a) => a.posture === "critical")) return "critical";
  if (list.some((a) => a.posture === "watch" || a.posture === "scanning")) return "watch";
  return "secure";
}

export function getAsset(id: string): Asset | undefined {
  return assets.find((a) => a.id === id);
}
