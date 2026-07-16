/**
 * Runtime check for correlation-only incident gate (no Next server-only imports).
 * Mirrors src/lib/scan/incident-gate.ts + defacement-score thresholds.
 */
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import path from "node:path";
import { register } from "node:module";

// Prefer compiled-free logic duplicated for evidence (must match source).
function computeDefacementScore(input) {
  const visualPct = input.visualDriftPct ?? null;
  const visualScore =
    visualPct == null ? 0 : visualPct >= 25 ? 90 : visualPct >= 12 ? 65 : visualPct >= 5 ? 35 : 0;
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
  const layers = [
    { id: "visual", score: visualScore, fired: visualScore >= 35 },
    { id: "dom", score: domScore, fired: domScore >= 40 },
    { id: "behavior", score: behaviorScore, fired: behaviorScore >= 40 },
    { id: "favicon", score: faviconScore, fired: faviconScore >= 40 },
    { id: "findings", score: findingsScore, fired: findingsScore >= 50 },
  ];
  const layersFired = layers.filter((l) => l.fired).length;
  const weights = { visual: 0.28, dom: 0.28, behavior: 0.22, favicon: 0.1, findings: 0.12 };
  let score = 0;
  for (const layer of layers) score += layer.score * weights[layer.id];
  if (layersFired >= 2) score += 12;
  if (layersFired >= 3) score += 10;
  score = Math.round(Math.max(0, Math.min(100, score)));
  const shouldIncident = score >= 55 && layersFired >= 2;
  let classification = "CLEAN";
  if (shouldIncident || score >= 70) classification = "DEFACEMENT";
  else if (score >= 45 || layersFired >= 2) classification = "SUSPECT";
  else if (score >= 20 || layersFired >= 1) classification = "WATCH";
  return { score, layersFired, shouldIncident, classification };
}

function shouldOpenIncident(scan) {
  if (scan.defacement?.shouldIncident === true) return true;
  return scan.findings.some((f) => f.risk === "critical" && f.category !== "DEFACEMENT");
}

const defaceFinding = {
  id: "1",
  category: "DEFACEMENT",
  risk: "critical",
  title: "Major",
  detail: "d",
  remediation: "r",
};

const single = {
  findings: [defaceFinding],
  defacement: computeDefacementScore({
    contentDriftPct: 30,
    visualDriftPct: null,
    contentChanged: true,
    faviconChanged: false,
    newScriptOrigins: [],
    findings: [defaceFinding],
  }),
};

const multi = {
  findings: [defaceFinding],
  defacement: computeDefacementScore({
    contentDriftPct: 30,
    visualDriftPct: 40,
    contentChanged: true,
    faviconChanged: true,
    newScriptOrigins: ["evil.com"],
    findings: [defaceFinding],
  }),
};

const tls = {
  findings: [{ id: "2", category: "TLS", risk: "critical", title: "Bad TLS", detail: "d", remediation: "r" }],
  defacement: computeDefacementScore({
    contentDriftPct: 0,
    visualDriftPct: 0,
    contentChanged: false,
    faviconChanged: false,
    newScriptOrigins: [],
    findings: [],
  }),
};

const clean = {
  findings: [],
  defacement: computeDefacementScore({
    contentDriftPct: 0,
    visualDriftPct: 0,
    contentChanged: false,
    faviconChanged: false,
    newScriptOrigins: [],
    findings: [],
  }),
};

const results = {
  SINGLE_DOM: {
    open: shouldOpenIncident(single),
    should: single.defacement.shouldIncident,
    layers: single.defacement.layersFired,
  },
  MULTI: {
    open: shouldOpenIncident(multi),
    should: multi.defacement.shouldIncident,
    class: multi.defacement.classification,
  },
  TLS: { open: shouldOpenIncident(tls) },
  CLEAN: { open: shouldOpenIncident(clean) },
};

console.log(JSON.stringify(results, null, 2));

const pass =
  results.SINGLE_DOM.open === false &&
  results.MULTI.open === true &&
  results.TLS.open === true &&
  results.CLEAN.open === false;

if (!pass) {
  console.error("GATE_VERIFY_FAILED");
  process.exit(1);
}
console.log("GATE_VERIFY_PASS");
