import { resolveTarget, SsrfError } from "./ssrf";
import { guardedFetch } from "./fetch";
import { diffDom, domHash } from "./dom";
import { auditHeaders } from "./headers";
import { checkTls, tlsFindings } from "./tls";
import { probePaths } from "./paths";
import { fingerprint, correlateOsv } from "./fingerprint";
import { aggregatePosture, postureScore, type Posture, type ScanFinding } from "./risk";

export interface ScanInput {
  target: string;
  baselineHtml?: string | null;
}

export interface ScanResult {
  ok: boolean;
  target: string;
  finalHost: string;
  scannedAt: string;
  elapsedMs: number;
  httpStatus: number;
  redirectedTo: string | null;
  posture: Posture;
  postureScore: number;
  domHash: string;
  driftPct: number;
  contentChanged: boolean;
  fingerprint: string | null;
  findings: ScanFinding[];
  html: string;
  error?: string;
}

/**
 * Runs the full defacement + vulnerability assessment against one target.
 * Every sub-check is independently fault-tolerant: a failure in one probe
 * (e.g. OSV timeout) never aborts the scan. This is the fail-open contract —
 * we always return findings we could gather, never a hard crash.
 */
export async function runScan(input: ScanInput): Promise<ScanResult> {
  const started = Date.now();
  const scannedAt = new Date().toISOString();

  let resolved;
  try {
    resolved = await resolveTarget(input.target);
  } catch (err) {
    const message = err instanceof SsrfError ? err.message : "Target validation failed";
    return emptyResult(input.target, "", scannedAt, Date.now() - started, message);
  }

  const targetUrl = resolved.url.toString();

  let page;
  try {
    page = await guardedFetch(targetUrl, { timeoutMs: 12_000, pin: resolved });
  } catch {
    return emptyResult(targetUrl, resolved.hostname, scannedAt, Date.now() - started, "Target could not be fetched");
  }

  const findings: ScanFinding[] = [];

  // 1. Security headers (synchronous, always available)
  findings.push(...auditHeaders(page.headers));

  // 2. Content / defacement diff
  const baseline = input.baselineHtml ?? null;
  let driftPct = 0;
  let contentChanged = false;
  const currentHash = domHash(page.body);
  if (baseline) {
    const diff = diffDom(baseline, page.body);
    driftPct = diff.driftPct;
    contentChanged = diff.changed;
    if (diff.driftPct >= 25) {
      findings.push({
        id: "deface-major",
        category: "DEFACEMENT",
        risk: "critical",
        title: "Major content deviation from baseline",
        detail: `Normalized content drift is ${diff.driftPct}% against the established baseline.`,
        remediation: "Compare current vs baseline capture; if unauthorized, restore and investigate the intrusion vector.",
        evidence: `drift ${diff.driftPct}%`,
      });
    } else if (diff.changed && diff.driftPct >= 8) {
      findings.push({
        id: "deface-drift",
        category: "DEFACEMENT",
        risk: "medium",
        title: "Content drift detected",
        detail: `Content changed by ${diff.driftPct}% since baseline (after noise normalization).`,
        remediation: "Review the change; re-baseline if the update is legitimate.",
        evidence: `drift ${diff.driftPct}%`,
      });
    }
  }

  // 3. Parallel: TLS, exposed paths, OSV correlation — all fault-isolated.
  const isHttps = resolved.url.protocol === "https:";
  const [tls, paths, cve] = await Promise.all([
    isHttps
      ? checkTls(resolved.hostname).then(tlsFindings).catch(() => [])
      : Promise.resolve<ScanFinding[]>([]),
    probePaths(targetUrl, resolved).catch(() => [] as ScanFinding[]),
    correlateOsv(fingerprint(page.headers, page.body)).catch(() => [] as ScanFinding[]),
  ]);
  findings.push(...tls, ...paths, ...cve);

  const fp = fingerprint(page.headers, page.body);

  return {
    ok: true,
    target: targetUrl,
    finalHost: resolved.hostname,
    scannedAt,
    elapsedMs: Date.now() - started,
    httpStatus: page.status,
    redirectedTo: page.redirectedTo,
    posture: aggregatePosture(findings),
    postureScore: postureScore(findings),
    domHash: currentHash,
    driftPct,
    contentChanged,
    fingerprint: fp.family,
    findings,
    html: page.body,
  };
}

function emptyResult(
  target: string,
  host: string,
  scannedAt: string,
  elapsedMs: number,
  error: string,
): ScanResult {
  return {
    ok: false,
    target,
    finalHost: host,
    scannedAt,
    elapsedMs,
    httpStatus: 0,
    redirectedTo: null,
    posture: "watch",
    postureScore: 0,
    domHash: "",
    driftPct: 0,
    contentChanged: false,
    fingerprint: null,
    findings: [],
    html: "",
    error,
  };
}
