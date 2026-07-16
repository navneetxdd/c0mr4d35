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
import { buildRemediation, type Remediation } from "./remediate";
import {
  aggregatePosture,
  postureScore,
  dedupeFindings,
  countBySeverity,
  type Posture,
  type Risk,
  type ScanFinding,
} from "./risk";
import { createProgress, type ProgressSink } from "./progress";
import { probePorts, portChangeFindings, type PortProbeResult } from "./ports";
import {
  discoverSubdomains,
  subdomainChangeFindings,
  type SubdomainResult,
} from "./subdomains";
import { lookupInternetDb, lookupShodanHost } from "./shodan";

export interface BehaviorBaseline {
  externalScriptOrigins?: string[];
  formActions?: string[];
  openPorts?: number[];
  subdomains?: string[];
}

export interface ScanInput {
  target: string;
  baselineHtml?: string | null;
  /** Prior scan's behavioral signals, for change detection. */
  baselineBehavior?: BehaviorBaseline | null;
  /** Cap crawl to just the root page (faster on-demand scans). */
  singlePage?: boolean;
  /** Optional stage reporter for progress UI / SSE. */
  onProgress?: ProgressSink;
  /** Optional Shodan API key (BYOK) for host/DNS enrichment. */
  shodanApiKey?: string | null;
}

export interface ScanSignals {
  externalScriptOrigins: string[];
  formActions: string[];
  hasPasswordInput: boolean;
  openPorts: number[];
  subdomains: string[];
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
  ports?: PortProbeResult[];
  subdomains?: SubdomainResult[];
  visualDriftPct?: number | null;
  screenshotPath?: string | null;
  baselineScreenshotPath?: string | null;
  diffPath?: string | null;
  screenshotUrl?: string | null;
  baselineScreenshotUrl?: string | null;
  diffUrl?: string | null;
  faviconHash?: string | null;
  faviconChanged?: boolean;
  faviconUrl?: string | null;
  baselineState?: "created" | "reused" | "provided" | "none";
  evidenceNotes?: string[];
  /** Generated copy-paste hardening (CSP + per-stack config); null when nothing to fix. */
  remediation?: Remediation | null;
  error?: string;
}

/**
 * Full defacement + vulnerability assessment against one target.
 * Fail-open: any single probe failure degrades gracefully.
 */
export async function runScan(input: ScanInput): Promise<ScanResult> {
  const started = Date.now();
  const scannedAt = new Date().toISOString();
  const report = createProgress(input.onProgress);
  const evidenceNotes: string[] = [];

  await report("resolve", "Validating target and resolving public address");

  let root;
  try {
    root = await fetchUrl(input.target, { followRedirects: true, timeoutMs: 12_000 });
  } catch (err) {
    const message = err instanceof SsrfError ? err.message : "Target could not be fetched";
    await report("error", message);
    return emptyResult(input.target, "", scannedAt, Date.now() - started, message);
  }

  const { final: page, resolved, chain } = root;
  const rootUrl = resolved.url.toString();
  const isHttps = resolved.url.protocol === "https:";
  await report("fetch", `Fetched ${rootUrl}`, `HTTP ${page.status}`);

  const crawlResult = input.singlePage
    ? {
        pages: [
          {
            url: rootUrl,
            status: page.status,
            headers: page.headers,
            body: page.body,
            contentType: page.headers["content-type"] ?? "",
          },
        ],
        discovered: [] as string[],
      }
    : await crawl(rootUrl, page, resolved).catch(() => ({
        pages: [
          {
            url: rootUrl,
            status: page.status,
            headers: page.headers,
            body: page.body,
            contentType: page.headers["content-type"] ?? "",
          },
        ],
        discovered: [] as string[],
      }));

  await report("crawl", `Crawled ${crawlResult.pages.length} page(s)`, `${crawlResult.discovered.length} links`);

  const findings: ScanFinding[] = [];
  const scriptOrigins = new Set<string>();
  const formActions = new Set<string>();
  let hasPasswordInput = false;

  const perPage = await Promise.allSettled(
    crawlResult.pages.map(async (p, index) => {
      const pageFindings: ScanFinding[] = [];
      if (index === 0) {
        pageFindings.push(...auditHeaders(p.headers, p.url));
        pageFindings.push(...auditCookies(p.headers["set-cookie"], isHttps, p.url));
      }
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

  const currentHash = domHash(page.body);
  let driftPct = 0;
  let contentChanged = false;
  if (input.baselineHtml) {
    const diff = diffDom(input.baselineHtml, page.body);
    driftPct = diff.driftPct;
    contentChanged = diff.changed;
    findings.push(...defacementFindings(diff.driftPct, diff.changed));
  }

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
  await report(
    "headers_tls_dns",
    "Completed header, TLS, and DNS probes",
    `fingerprint=${fp.family ?? "none"}`,
  );
  await report("paths_cors", "Completed path, CORS, and method probes");
  await report("screenshot_diff", "Visual capture runs after passive probes");

  let ports: PortProbeResult[] = [];
  let subdomains: SubdomainResult[] = [];

  try {
    const portProbe = await probePorts(resolved.address || resolved.hostname);
    ports = portProbe.results;
    findings.push(...portProbe.findings);
    evidenceNotes.push(...portProbe.notes);

    const idb = await lookupInternetDb(resolved.address);
    evidenceNotes.push(...idb.notes);
    findings.push(...idb.findings);
    const internetDbHostnames = [...(idb.record?.hostnames ?? [])];
    if (idb.record?.ports.length) {
      const seen = new Set(ports.map((p) => p.port));
      const now = new Date().toISOString();
      for (const port of idb.record.ports) {
        if (seen.has(port)) continue;
        ports.push({ port, state: "open", rttMs: 0, probedAt: now });
        seen.add(port);
      }
      evidenceNotes.push(
        `Merged ${idb.record.ports.length} InternetDB port(s) into open-port set (indexed, not live TCP).`,
      );
    }

    if (input.shodanApiKey?.trim()) {
      const shodanHost = await lookupShodanHost(resolved.address, input.shodanApiKey);
      evidenceNotes.push(...shodanHost.notes);
      findings.push(...shodanHost.findings);
      if (shodanHost.record?.ports.length) {
        const seen = new Set(ports.map((p) => p.port));
        const now = new Date().toISOString();
        for (const port of shodanHost.record.ports) {
          if (seen.has(port)) continue;
          ports.push({ port, state: "open", rttMs: 0, probedAt: now });
          seen.add(port);
        }
      }
      for (const host of shodanHost.record?.hostnames ?? []) {
        if (!internetDbHostnames.includes(host)) internetDbHostnames.push(host);
      }
    } else {
      evidenceNotes.push(
        "Shodan host API skipped — add a Shodan key in Settings for full banner/CVE enrichment.",
      );
    }

    findings.push(
      ...portChangeFindings(resolved.hostname, input.baselineBehavior?.openPorts, ports),
    );
    await report(
      "ports",
      "Completed TCP + Shodan/InternetDB port recon",
      `${ports.filter((p) => p.state === "open").length} open`,
    );

    try {
      const subProbe = await discoverSubdomains(resolved.hostname, {
        shodanApiKey: input.shodanApiKey,
        extraHostnames: internetDbHostnames,
      });
      subdomains = subProbe.results;
      findings.push(...subProbe.findings);
      findings.push(...subdomainChangeFindings(input.baselineBehavior?.subdomains, subdomains));
      evidenceNotes.push(...subProbe.notes);
      await report(
        "subdomains",
        "Completed CT/Shodan/InternetDB subdomain discovery",
        `${subdomains.length} names`,
      );
    } catch (error) {
      evidenceNotes.push(
        `Subdomain discovery skipped: ${error instanceof Error ? error.message : "unknown error"}`,
      );
      await report("subdomains", "Subdomain discovery unavailable");
    }
  } catch (error) {
    evidenceNotes.push(
      `Port probe skipped: ${error instanceof Error ? error.message : "unknown error"}`,
    );
    await report("ports", "Port probe unavailable");
    try {
      const subProbe = await discoverSubdomains(resolved.hostname, {
        shodanApiKey: input.shodanApiKey,
      });
      subdomains = subProbe.results;
      findings.push(...subProbe.findings);
      findings.push(...subdomainChangeFindings(input.baselineBehavior?.subdomains, subdomains));
      evidenceNotes.push(...subProbe.notes);
      await report("subdomains", "Completed subdomain discovery", `${subdomains.length} names`);
    } catch (subErr) {
      evidenceNotes.push(
        `Subdomain discovery skipped: ${subErr instanceof Error ? subErr.message : "unknown error"}`,
      );
      await report("subdomains", "Subdomain discovery unavailable");
    }
  }

  const openPorts = ports.filter((p) => p.state === "open").map((p) => p.port);
  const subdomainNames = subdomains.map((s) => s.subdomain);
  const deduped = dedupeFindings(findings);

  const remediation = buildRemediation({
    finalHost: resolved.hostname,
    isHttps,
    fingerprint: fp.family,
    techStack: fp.components.map((c) => c.family),
    findings: deduped,
    externalScriptOrigins: [...scriptOrigins],
    formActions: [...formActions],
  });

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
      openPorts,
      subdomains: subdomainNames,
    },
    findings: deduped,
    html: page.body,
    ports,
    subdomains,
    visualDriftPct: null,
    screenshotPath: null,
    baselineScreenshotPath: null,
    diffPath: null,
    screenshotUrl: null,
    baselineScreenshotUrl: null,
    diffUrl: null,
    faviconHash: null,
    faviconChanged: false,
    faviconUrl: null,
    baselineState: "none",
    evidenceNotes,
    remediation,
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
    redirectChain: [],
    pagesScanned: 0,
    discoveredLinks: 0,
    // Explicit failure — not a monitored "watch" posture.
    posture: "secure",
    postureScore: 0,
    domHash: "",
    driftPct: 0,
    contentChanged: false,
    fingerprint: null,
    techStack: [],
    severityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    signals: {
      externalScriptOrigins: [],
      formActions: [],
      hasPasswordInput: false,
      openPorts: [],
      subdomains: [],
    },
    findings: [],
    html: "",
    ports: [],
    subdomains: [],
    visualDriftPct: null,
    screenshotPath: null,
    baselineScreenshotPath: null,
    diffPath: null,
    screenshotUrl: null,
    baselineScreenshotUrl: null,
    diffUrl: null,
    faviconHash: null,
    faviconChanged: false,
    faviconUrl: null,
    baselineState: "none",
    evidenceNotes: [],
    error,
  };
}
