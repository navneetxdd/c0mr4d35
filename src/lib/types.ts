export type Posture = "secure" | "watch" | "critical" | "scanning" | "pending";
/**
 * Product-side finding severity for the monitored asset. Intentionally NOT
 * the hackathon SL-1/SL-2/SL-3 staking levels, which apply to bug reports
 * filed against us during the live game, not to security findings we surface.
 */
export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type Role = "admin" | "analyst" | "viewer";
export type ScanTrigger = "CRON" | "MANUAL";
export type ScanStatus = "queued" | "scanning" | "done" | "failed";
export type DiffMode = "side-by-side" | "reveal" | "heatmap";
export type IncidentStatus = "open" | "acknowledged" | "resolved";
export type FindingGroup =
  | "DEFACEMENT"
  | "BEHAVIOR"
  | "HEADERS"
  | "COOKIES"
  | "CORS"
  | "CONTENT"
  | "METHODS"
  | "TLS"
  | "DNS"
  | "EXPOSED PATHS"
  | "CVE"
  | "PORTS"
  | "SUBDOMAINS";

export interface Asset {
  id: string;
  name: string;
  host: string;
  posture: Posture;
  driftScore: number;
  driftHistory: number[];
  lastCheckAt: string;
  thumbnail: string;
  baselineCapture: string;
  currentCapture: string;
  diffCapture?: string;
  openIncident: boolean;
  scanIntervalMin: number;
}

export interface FeedEvent {
  id: string;
  at: string;
  posture: Posture;
  message: string;
}

export interface ScanEntry {
  id: string;
  at: string;
  driftPct: number;
  visualDriftPct?: number | null;
  posture: Posture;
  trigger: ScanTrigger;
  durationMs: number;
  status: ScanStatus;
}

export interface VisualEvidence {
  baselineState: "created" | "reused" | "provided" | "none";
  domDriftPct: number;
  visualDriftPct: number | null;
  baselineHtml: string | null;
  baselineCapture: string | null;
  currentCapture: string | null;
  diffCapture: string | null;
  faviconHash: string | null;
  faviconChanged: boolean;
  faviconUrl: string | null;
  notes: string[];
  ports?: Array<{
    port: number;
    state: "open" | "closed" | "timeout";
    rttMs: number;
    probedAt: string;
  }>;
  subdomains?: Array<{
    subdomain: string;
    source: "ct" | "wordlist";
    ips: string[];
    queriedAt: string;
  }>;
}

export interface ChangeRegion {
  id: string;
  label: string;
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface AiVerdict {
  verdict: "BASELINE HELD" | "DRIFT DETECTED" | "DEFACEMENT";
  confidence: number;
  summary: string;
  indicators: { label: string; posture: Posture }[];
}

export interface Finding {
  id: string;
  group: FindingGroup;
  severity: RiskLevel;
  title: string;
  detail: string;
  remediation: string;
  evidence?: string;
  observedUrl?: string;
  cveId?: string;
  stackFamily?: string;
}

export interface Incident {
  id: string;
  severity: RiskLevel;
  assetId: string;
  assetName: string;
  type: string;
  detectedAt: string;
  status: IncidentStatus;
  mttdSec: number;
  assignee: string | null;
}

export interface AuditEntry {
  seq: number;
  at: string;
  actor: string;
  action: string;
  target: string;
  prevHash: string;
  thisHash: string;
}

export interface Member {
  id: string;
  email: string;
  role: Role;
  joinedAt: string;
}

export interface Telemetry {
  assets: number;
  scans24h: number;
  openIncidents: number;
  /** Average MTTD from incidents that recorded one; null when no samples. */
  mttdSec: number | null;
  /** Successful scans / total scans in last 24h; null when no scans yet. */
  scanSuccessPct: number | null;
}
