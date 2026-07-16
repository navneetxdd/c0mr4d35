/**
 * Product-side risk model. NOTE: these are the *monitored asset's* security
 * finding levels — deliberately NOT the hackathon's SL-1/SL-2/SL-3 staking
 * levels, which describe bug reports filed against us during the live game.
 */
export type Risk = "critical" | "high" | "medium" | "low" | "info";

export type FindingCategory =
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

export interface ScanFinding {
  id: string;
  category: FindingCategory;
  risk: Risk;
  title: string;
  detail: string;
  remediation: string;
  /** Short evidence snippet (kept small — never dump full bodies). */
  evidence?: string;
  /** External reference (advisory URL, spec). */
  reference?: string;
  /** OWASP Top 10 (2021) mapping, e.g. "A05:2021 Security Misconfiguration". */
  owasp?: string;
  /** CWE id, e.g. "CWE-614". */
  cwe?: string;
  /** Which crawled page the finding was observed on (origin-relative). */
  url?: string;
}

export const RISK_WEIGHT: Record<Risk, number> = {
  critical: 45,
  high: 20,
  medium: 10,
  low: 4,
  info: 0,
};

export const RISK_ORDER: Record<Risk, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export type Posture = "secure" | "watch" | "critical";

/**
 * Aggregate posture from the worst finding present. One critical => critical;
 * any high/medium => watch; otherwise secure.
 */
export function aggregatePosture(findings: ScanFinding[]): Posture {
  if (findings.some((f) => f.risk === "critical")) return "critical";
  if (findings.some((f) => f.risk === "high" || f.risk === "medium")) return "watch";
  return "secure";
}

/** 0–100 security posture score; 100 is clean. Diminishing penalty so a long
 *  tail of low findings can't swamp a single critical. */
export function postureScore(findings: ScanFinding[]): number {
  const penalty = findings.reduce((sum, f) => sum + RISK_WEIGHT[f.risk], 0);
  return Math.max(0, Math.round(100 - Math.min(95, penalty)));
}

/** Stable severity-first sort for presentation. */
export function sortFindings(findings: ScanFinding[]): ScanFinding[] {
  return [...findings].sort((a, b) => RISK_ORDER[a.risk] - RISK_ORDER[b.risk]);
}

/** De-duplicates findings by id, keeping the highest-severity instance and
 *  recording how many pages it appeared on. */
export function dedupeFindings(findings: ScanFinding[]): ScanFinding[] {
  const byId = new Map<string, ScanFinding>();
  for (const f of findings) {
    const existing = byId.get(f.id);
    if (!existing || RISK_ORDER[f.risk] < RISK_ORDER[existing.risk]) {
      byId.set(f.id, f);
    }
  }
  return sortFindings([...byId.values()]);
}

export function countBySeverity(findings: ScanFinding[]): Record<Risk, number> {
  const counts: Record<Risk, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.risk] += 1;
  return counts;
}
