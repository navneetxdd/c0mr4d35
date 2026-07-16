/**
 * Multi-signal defacement confidence (0–100).
 * Fuses independent integrity layers so a single noisy pixel/DOM blip
 * does not open an incident — XICTRAQ-style correlation for PS-005.
 */

import type { ScanFinding } from "./risk";

export interface DefacementLayer {
  id: "visual" | "dom" | "behavior" | "favicon" | "findings";
  label: string;
  score: number;
  fired: boolean;
  detail: string;
}

export interface DefacementScore {
  score: number;
  layers: DefacementLayer[];
  layersFired: number;
  /** Open / escalate only when score and layer count both clear thresholds. */
  shouldIncident: boolean;
  classification: "CLEAN" | "WATCH" | "SUSPECT" | "DEFACEMENT";
}

export interface DefacementScoreInput {
  contentDriftPct: number;
  visualDriftPct?: number | null;
  contentChanged: boolean;
  faviconChanged?: boolean;
  newScriptOrigins?: string[];
  findings: ScanFinding[];
}

const INCIDENT_SCORE = 55;
const INCIDENT_LAYERS = 2;

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}

export function computeDefacementScore(input: DefacementScoreInput): DefacementScore {
  const visualPct = input.visualDriftPct ?? null;
  const visualScore =
    visualPct == null
      ? 0
      : visualPct >= 25
        ? 90
        : visualPct >= 12
          ? 65
          : visualPct >= 5
            ? 35
            : 0;

  const domScore =
    input.contentDriftPct >= 25
      ? 95
      : input.contentDriftPct >= 12
        ? 70
        : input.contentDriftPct >= 8 && input.contentChanged
          ? 45
          : input.contentChanged
            ? 20
            : 0;

  const newOrigins = input.newScriptOrigins ?? [];
  const behaviorScore =
    newOrigins.length >= 3 ? 85 : newOrigins.length === 2 ? 60 : newOrigins.length === 1 ? 40 : 0;

  const faviconScore = input.faviconChanged ? 55 : 0;

  const defaceFindings = input.findings.filter((f) => f.category === "DEFACEMENT");
  const findingsScore = defaceFindings.some((f) => f.risk === "critical")
    ? 90
    : defaceFindings.some((f) => f.risk === "high" || f.risk === "medium")
      ? 55
      : 0;

  const layers: DefacementLayer[] = [
    {
      id: "visual",
      label: "Visual pixel drift",
      score: visualScore,
      fired: visualScore >= 35,
      detail:
        visualPct == null
          ? "No visual baseline comparison"
          : `${visualPct.toFixed(1)}% pixels changed`,
    },
    {
      id: "dom",
      label: "DOM / content drift",
      score: domScore,
      fired: domScore >= 40,
      detail: `${input.contentDriftPct}% normalized content drift`,
    },
    {
      id: "behavior",
      label: "New script origins",
      score: behaviorScore,
      fired: behaviorScore >= 40,
      detail:
        newOrigins.length === 0
          ? "No new external script hosts"
          : `${newOrigins.length} new: ${newOrigins.slice(0, 3).join(", ")}`,
    },
    {
      id: "favicon",
      label: "Favicon identity",
      score: faviconScore,
      fired: faviconScore >= 40,
      detail: input.faviconChanged ? "Favicon fingerprint changed" : "Favicon unchanged",
    },
    {
      id: "findings",
      label: "Defacement findings",
      score: findingsScore,
      fired: findingsScore >= 50,
      detail:
        defaceFindings.length === 0
          ? "No DEFACEMENT-category findings"
          : `${defaceFindings.length} finding(s)`,
    },
  ];

  const fired = layers.filter((l) => l.fired);
  const layersFired = fired.length;

  // Weighted blend; prefer fired layers so quiet channels don't dilute signal.
  const weights: Record<DefacementLayer["id"], number> = {
    visual: 0.28,
    dom: 0.28,
    behavior: 0.22,
    favicon: 0.1,
    findings: 0.12,
  };
  let score = 0;
  for (const layer of layers) {
    score += layer.score * weights[layer.id];
  }
  // Correlation boost when ≥2 independent layers fire.
  if (layersFired >= 2) score += 12;
  if (layersFired >= 3) score += 10;
  score = Math.round(clamp(score, 0, 100));

  const shouldIncident = score >= INCIDENT_SCORE && layersFired >= INCIDENT_LAYERS;

  let classification: DefacementScore["classification"] = "CLEAN";
  if (shouldIncident || score >= 70) classification = "DEFACEMENT";
  else if (score >= 45 || layersFired >= 2) classification = "SUSPECT";
  else if (score >= 20 || layersFired >= 1) classification = "WATCH";

  return { score, layers, layersFired, shouldIncident, classification };
}

/** Origins present now but absent from the prior baseline set. */
export function newScriptOrigins(
  current: string[] | undefined,
  baseline: string[] | undefined,
): string[] {
  if (!current?.length) return [];
  const prior = new Set((baseline ?? []).map((o) => o.toLowerCase()));
  return current.filter((o) => !prior.has(o.toLowerCase()));
}
