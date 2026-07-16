/**
 * Product-side risk model. NOTE: these are the *monitored asset's* security
 * finding levels — deliberately NOT the hackathon's SL-1/SL-2/SL-3 staking
 * levels, which describe bug reports filed against us during the live game.
 */
export type Risk = "critical" | "high" | "medium" | "low" | "info";

export type FindingCategory =
  | "DEFACEMENT"
  | "HEADERS"
  | "TLS"
  | "EXPOSED PATHS"
  | "CVE";

export interface ScanFinding {
  id: string;
  category: FindingCategory;
  risk: Risk;
  title: string;
  detail: string;
  remediation: string;
  evidence?: string;
  reference?: string;
}

export const RISK_WEIGHT: Record<Risk, number> = {
  critical: 100,
  high: 70,
  medium: 40,
  low: 15,
  info: 0,
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

/** 0–100 security posture score; 100 is clean. */
export function postureScore(findings: ScanFinding[]): number {
  const penalty = findings.reduce((sum, f) => sum + RISK_WEIGHT[f.risk], 0);
  return Math.max(0, Math.round(100 - Math.min(100, penalty)));
}
