/**
 * Regression check for the correlation-only incident gate.
 * Imports the REAL pure scorer + gate (no duplication, no server-only chain),
 * so retuning thresholds in source is exercised here directly.
 *
 * Run: npx tsx scripts/verify-incident-gate.ts
 */
import { computeDefacementScore } from "../src/lib/scan/defacement-score";
import { shouldOpenIncident, incidentTypeFromScan } from "../src/lib/scan/incident-gate";
import type { ScanFinding } from "../src/lib/scan/risk";

const defaceFinding: ScanFinding = {
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
  findings: [
    { id: "2", category: "TLS", risk: "critical", title: "Bad TLS", detail: "d", remediation: "r" } as ScanFinding,
  ],
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
  findings: [] as ScanFinding[],
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
    type: incidentTypeFromScan(multi),
    class: multi.defacement.classification,
  },
  TLS: { open: shouldOpenIncident(tls), type: incidentTypeFromScan(tls) },
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
