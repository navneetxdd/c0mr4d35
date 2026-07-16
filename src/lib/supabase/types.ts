/** Application role hierarchy (mirrors the app_role enum + RLS policies). */
export type AppRole = "admin" | "analyst" | "viewer";

export const ROLE_RANK: Record<AppRole, number> = { admin: 3, analyst: 2, viewer: 1 };

export interface Profile {
  id: string;
  email: string | null;
  role: AppRole;
  created_at: string;
}

export interface Asset {
  id: string;
  name: string;
  url: string;
  owner: string | null;
  monitoring_enabled: boolean;
  scan_interval_min: number;
  created_at: string;
  updated_at: string;
  last_scanned_at?: string | null;
}

export interface Scan {
  id: string;
  asset_id: string;
  status: "queued" | "scanning" | "done" | "error";
  trigger: "manual" | "cron";
  http_status: number | null;
  posture: "secure" | "watch" | "critical" | null;
  posture_score: number | null;
  drift_pct: number | null;
  pages_scanned: number | null;
  tech_stack: string[];
  severity_counts: Record<string, number>;
  signals: Record<string, unknown>;
  ai_verdict: unknown | null;
  dom_hash: string | null;
  screenshot_path: string | null;
  diff_path?: string | null;
  visual_drift_pct?: number | null;
  favicon_hash?: string | null;
  favicon_changed?: boolean;
  error: string | null;
  created_by: string | null;
  started_at: string;
  finished_at: string | null;
}

export interface Baseline {
  id: string;
  asset_id: string;
  dom_hash: string | null;
  signals: Record<string, unknown>;
  screenshot_path: string | null;
  html_snapshot?: string | null;
  favicon_hash?: string | null;
  established_by: string | null;
  established_at: string;
}

export interface AdhocBaseline {
  target_key: string;
  target_url: string;
  html_snapshot: string | null;
  signals: Record<string, unknown>;
  screenshot_path: string | null;
  favicon_hash: string | null;
  created_at: string;
  updated_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  asset_id: string;
  category: string;
  risk: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string | null;
  remediation: string | null;
  evidence: string | null;
  reference: string | null;
  owasp: string | null;
  cwe: string | null;
  url: string | null;
  created_at: string;
}

export interface Alert {
  id: string;
  asset_id: string | null;
  scan_id: string | null;
  severity: Finding["risk"];
  message: string;
  channel: string;
  delivered: boolean;
  created_at: string;
}

export interface AuditEntry {
  seq: number;
  actor: string | null;
  action: string;
  target_table: string | null;
  target_id: string | null;
  detail: Record<string, unknown> | null;
  prev_hash: string | null;
  this_hash: string;
  created_at: string;
}
