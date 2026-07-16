import type { Finding as DbFinding } from "@/lib/supabase/types";
import type { Finding, RiskLevel } from "@/lib/types";

const RISK_MAP: Record<string, RiskLevel> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "LOW",
};

export function mapFindingRow(f: DbFinding): Finding {
  return {
    id: f.id,
    group: f.category as Finding["group"],
    severity: RISK_MAP[f.risk] ?? "LOW",
    title: f.title,
    detail: f.detail ?? "",
    remediation: f.remediation ?? "",
    cveId: f.category === "CVE" ? f.reference ?? undefined : undefined,
    stackFamily: f.evidence ?? undefined,
  };
}
