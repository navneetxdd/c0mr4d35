import type { DefacementScore } from "./defacement-score";
import type { ScanFinding } from "./risk";

export interface IncidentGateInput {
  defacement?: DefacementScore | null;
  findings: ScanFinding[];
}

/**
 * Open an incident only when multi-signal defacement clears its gate,
 * or a non-defacement critical finding exists (TLS/CVE/exposed path, etc.).
 * Single-signal DOM drift alone must not escalate — alerts still fire.
 */
export function shouldOpenIncident(scan: IncidentGateInput): boolean {
  if (scan.defacement?.shouldIncident === true) return true;
  return scan.findings.some((f) => f.risk === "critical" && f.category !== "DEFACEMENT");
}

export function incidentTypeFromScan(scan: IncidentGateInput): string {
  if (
    scan.defacement?.shouldIncident === true ||
    scan.defacement?.classification === "DEFACEMENT"
  ) {
    return "DEFACEMENT";
  }
  if (scan.findings.some((f) => f.category === "DEFACEMENT")) return "DEFACEMENT";
  if (scan.findings.some((f) => f.risk === "critical")) return "CRITICAL FINDING";
  return "POSTURE DEGRADED";
}
