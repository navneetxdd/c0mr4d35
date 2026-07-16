import { fetchUrl, SsrfError } from "./client";
import { crawl } from "./crawl";
import { diffDom, domHash } from "./dom";
import { auditHeaders } from "./headers";
import { auditCookies } from "./cookies";
import { analyzeContent, extractSignals } from "./content";
import { probeCors } from "./cors";
import { checkMethods } from "./methods";
import { checkTls, tlsFindings, legacyTlsFindings } from "./tls";
import { checkDns } from "./dns";
import { probePaths } from "./paths";
import { fingerprint, correlateOsv } from "./fingerprint";
import {
  aggregatePosture,
  postureScore,
  dedupeFindings,
  countBySeverity,
  type Posture,
  type Risk,
  type ScanFinding,
} from "./risk";

export interface BehaviorBaseline {
  externalScriptOrigins?: string[];
  formActions?: string[];
}

export interface ScanInput {
  target: string;
  baselineHtml?: string | null;
  /** Prior scan's behavioral signals, for change detection. */
  baselineBehavior?: BehaviorBaseline | null;
  /** Cap crawl to just the root page (faster on-demand scans). */
  singlePage?: boolean;
}

export interface ScanSignals {
  externalScriptOrigins: string[];
  formActions: string[];
  hasPasswordInput: boolean;
}

export interface ScanResult {
  ok: boolean;
  target: string;
  finalHost: string;
  scannedAt: string;
  elapsedMs: number;
  httpStatus: number;
  redirectedTo: string | null;
  redirectChain: string[];
  pagesScanned: number;
  discoveredLinks: number;
  posture: Posture;
  postureScore: number;
  domHash: string;
  driftPct: number;
  contentChanged: boolean;
  fingerprint: string | null;
  techStack: string[];
  severityCounts: Record<Risk, number>;
  signals: ScanSignals;
  findings: ScanFinding[];
  html: string;
  error?: string;
}

/**
 * Full defacement + vulnerability assessment against one target. The engine:
 *   1. resolves + SSRF-validates + fetches the root (following redirects safely)
 *   2. crawls a bounded set of same-origin pages
 *   3. runs per-page checks (headers, cookies, content) and origin-level checks
 *      (paths, CORS, methods, TLS, DNS, CVE) — every probe fault-isolated
 *   4. diffs content vs baseline for defacement, and behavioral signals vs the
 *      prior scan for suspicious change
 * Fail-open: any single probe failure degrades gracefully; we return what we
 * gathered rather than crashing.
 */
export async function runScan(input: ScanInput): Promise<ScanResult> {
  const started = Date.now();
  const scannedAt = new Date().toISOString();

  let root;
  try {
    root = await fetchUrl(input.target, { followRedirects: true, timeoutMs: 12_000 });
  } catch (err) {
    const message = err instanceof SsrfError ? err.message : "Target could not be fetched";
    return emptyResult(input.target, "", scannedAt, Date.now() - started, message);
  }

  const { final: page, resolved, chain } = root;
  const rootUrl = resolved.url.toString();
  const isHttps = resolved.url.protocol === "https:";

  // Crawl (unless single-page requested).
  const crawlResult = input.singlePage
    ? { pages: [{ url: rootUrl, status: page.status, headers: page.headers, body: page.body, contentType: page.headers["content-type"] ?? "" }], discovered: [] }
    : await crawl(rootUrl, page, resolved).catch(() => ({
        pages: [{ url: rootUrl, status: page.status, headers: page.headers, body: page.body, contentType: page.headers["content-type"] ?? "" }],
        discovered: [],
      }));

  const findings: ScanFinding[] = [];

  // Per-page checks (fault-isolated per page).
  const scriptOrigins = new Set<string>();
  const formActions = new Set<string>();
  let hasPasswordInput = false;

  const perPage = await Promise.allSettled(
    crawlResult.pages.map(async (p) => {
      const pageFindings: ScanFinding[] = [];
      pageFindings.push(...auditHeaders(p.headers, p.url));
      pageFindings.push(...auditCookies(p.headers["set-cookie"], isHttps, p.url));
      pageFindings.push(...(await analyzeContent(p.body, p.url, resolved).catch(() => [])));
      const sig = extractSignals(p.body, p.url);
      return { pageFindings, sig };
    }),
  );
  for (const r of perPage) {
    if (r.status === "fulfilled") {
      findings.push(...r.value.pageFindings);
      for (const o of r.value.sig.externalScriptOrigins) scriptOrigins.add(o);
      for (const a of r.value.sig.formActions) formActions.add(a);
      if (r.value.sig.hasPasswordInput) hasPasswordInput = true;
    }
  }

  // Content / defacement diff (root page vs stored baseline).
  const currentHash = domHash(page.body);
  let driftPct = 0;
  let contentChanged = false;
  if (input.baselineHtml) {
    const diff = diffDom(input.baselineHtml, page.body);
    driftPct = diff.driftPct;
    contentChanged = diff.changed;
    findings.push(...defacementFindings(diff.driftPct, diff.changed));
  }

  // Behavioral change vs prior scan (new external script origins are a classic
  // defacement/supply-chain signal).
  if (input.baselineBehavior?.externalScriptOrigins) {
    const prev = new Set(input.baselineBehavior.externalScriptOrigins);
    const added = [...scriptOrigins].filter((o) => !prev.has(o));
    if (added.length) {
      findings.push({
        id: "behavior-new-script-origin",
        category: "BEHAVIOR",
        risk: "high",
        title: "New third-party script origin appeared",
        detail: `Since the last scan, script(s) from new origin(s) were added: ${added.slice(0, 5).join(", ")}. Unexpected new script sources can indicate defacement or supply-chain compromise.`,
        remediation: "Verify these script sources are intentional; if not, treat as a possible compromise and investigate.",
        evidence: added.slice(0, 5).join(", "),
        owasp: "A08:2021 Software and Data Integrity Failures",
        cwe: "CWE-829",
      });
    }
  }

  // Origin-level checks (once), all fault-isolated and run in parallel.
  const fp = fingerprint(page.headers, page.body);
  const [paths, cors, methods, tls, legacyTls, dns, cve] = await Promise.all([
    probePaths(rootUrl, resolved).catch(() => [] as ScanFinding[]),
    probeCors(rootUrl, resolved).catch(() => [] as ScanFinding[]),
    checkMethods(rootUrl, resolved).catch(() => [] as ScanFinding[]),
    isHttps ? checkTls(resolved.hostname).then(tlsFindings).catch(() => [] as ScanFinding[]) : Promise.resolve<ScanFinding[]>([]),
    isHttps ? legacyTlsFindings(resolved.hostname).catch(() => [] as ScanFinding[]) : Promise.resolve<ScanFinding[]>([]),
    checkDns(resolved.hostname).catch(() => [] as ScanFinding[]),
    correlateOsv(fp).catch(() => [] as ScanFinding[]),
  ]);
  findings.push(...paths, ...cors, ...methods, ...tls, ...legacyTls, ...dns, ...cve);

  const deduped = dedupeFindings(findings);

  return {
    ok: true,
    target: rootUrl,
    finalHost: resolved.hostname,
    scannedAt,
    elapsedMs: Date.now() - started,
    httpStatus: page.status,
    redirectedTo: chain.length ? rootUrl : page.redirectedTo,
    redirectChain: chain,
    pagesScanned: crawlResult.pages.length,
    discoveredLinks: crawlResult.discovered.length,
    posture: aggregatePosture(deduped),
    postureScore: postureScore(deduped),
    domHash: currentHash,
    driftPct,
    contentChanged,
    fingerprint: fp.family,
    techStack: fp.components.map((c) => c.family),
    severityCounts: countBySeverity(deduped),
    signals: {
      externalScriptOrigins: [...scriptOrigins],
      formActions: [...formActions],
      hasPasswordInput,
    },
    findings: deduped,
    html: page.body,
  };
}

function defacementFindings(driftPct: number, changed: boolean): ScanFinding[] {
  if (driftPct >= 25) {
    return [
      {
        id: "deface-major",
        category: "DEFACEMENT",
        risk: "critical",
        title: "Major content deviation from baseline",
        detail: `Normalized content drift is ${driftPct}% against the established baseline — consistent with defacement.`,
        remediation: "Compare current vs baseline capture; if unauthorized, restore and investigate the intrusion vector.",
        evidence: `drift ${driftPct}%`,
        owasp: "A05:2021 Security Misconfiguration",
      },
    ];
  }
  if (changed && driftPct >= 8) {
    return [
      {
        id: "deface-drift",
        category: "DEFACEMENT",
        risk: "medium",
        title: "Content drift detected",
        detail: `Content changed by ${driftPct}% since baseline (after noise normalization).`,
        remediation: "Review the change; re-baseline if the update is legitimate.",
        evidence: `drift ${driftPct}%`,
      },
    ];
  }
  return [];
}

function emptyResult(target: string, host: string, scannedAt: string, elapsedMs: number, error: string): ScanResult {
  return {
    ok: false,
    target,
    finalHost: host,
    scannedAt,
    elapsedMs,
    httpStatus: 0,
    redirectedTo: null,
    redirectChain: [],
    pagesScanned: 0,
    discoveredLinks: 0,
    posture: "watch",
    postureScore: 0,
    domHash: "",
    driftPct: 0,
    contentChanged: false,
    fingerprint: null,
    techStack: [],
    severityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    signals: { externalScriptOrigins: [], formActions: [], hasPasswordInput: false },
    findings: [],
    html: "",
    error,
  };
}
