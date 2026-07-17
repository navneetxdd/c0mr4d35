import { createHash } from "node:crypto";
import { fetchUrl } from "./client";
import type { ScanFinding } from "./risk";
import type { BehaviorBaseline } from "./index";

export interface ScriptSignal {
  src: string | null;
  sha256: string;
}

export function sha256(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

function absUrl(href: string, base: string): URL | null {
  try {
    return new URL(href, base);
  } catch {
    return null;
  }
}

/**
 * Extracts all script tags (inline and external) and computes their SHA-256 hashes.
 * Also scans the HTML for all outbound egress domains.
 */
export async function extractIntegrity(
  html: string,
  pageUrl: string,
  targetHost: string,
): Promise<{ scripts: ScriptSignal[]; egress: string[]; notes: string[] }> {
  const notes: string[] = [];
  const scripts: ScriptSignal[] = [];
  const egress = new Set<string>();

  const pageOrigin = new URL(pageUrl).origin;
  const targetApex = targetHost.split(".").slice(-2).join("."); // e.g. example.com from sub.example.com

  // 1. Extract and hash scripts
  const SCRIPT_TAG_REGEX = /<script\b([^>]*?)>([\s\S]*?)<\/script>/gi;
  const SRC_REGEX = /\bsrc=["']([^"']+)["']/i;

  let match: RegExpExecArray | null;
  SCRIPT_TAG_REGEX.lastIndex = 0;

  const externalFetches: Promise<{ src: string; sha256: string; error?: string }>[] = [];

  while ((match = SCRIPT_TAG_REGEX.exec(html)) !== null) {
    const attrs = match[1] ?? "";
    const body = match[2] ?? "";
    const srcMatch = attrs.match(SRC_REGEX);

    if (srcMatch && srcMatch[1]) {
      const rawSrc = srcMatch[1];
      const resolved = absUrl(rawSrc, pageUrl);
      if (resolved) {
        const srcUrl = resolved.toString();
        // Asynchronously fetch external script content to hash it
        externalFetches.push(
          fetchUrl(srcUrl, { timeoutMs: 4000 })
            .then((res) => ({
              src: srcUrl,
              sha256: sha256(res.final.body),
            }))
            .catch((err) => {
              // Fallback to hashing URL if fetch fails
              return {
                src: srcUrl,
                sha256: sha256(`url:${srcUrl}`),
                error: err instanceof Error ? err.message : String(err),
              };
            }),
        );
      }
    } else if (body.trim()) {
      // Inline script
      scripts.push({
        src: null,
        sha256: sha256(body),
      });
    }
  }

  // Resolve all external script fetches
  const fetchedScripts = await Promise.all(externalFetches);
  for (const item of fetchedScripts) {
    scripts.push({ src: item.src, sha256: item.sha256 });
    if (item.error) {
      notes.push(`Integrity: failed to fetch script content for ${item.src} (${item.error}), used URL fallback hash.`);
    }
  }

  // 2. Extract outbound egress domains
  // Matches any http(s) URL inside the HTML
  const URL_REGEX = /https?:\/\/([a-zA-Z0-9.-]+)/gi;
  let urlMatch: RegExpExecArray | null;
  URL_REGEX.lastIndex = 0;

  while ((urlMatch = URL_REGEX.exec(html)) !== null) {
    const domain = urlMatch[1]!.toLowerCase();
    
    // Filter out target host, target apex domain, and current page origin
    const isLocalOrTarget =
      domain === targetHost ||
      domain.endsWith(`.${targetApex}`) ||
      domain === new URL(pageOrigin).hostname ||
      domain === "localhost" ||
      domain === "127.0.0.1";

    if (!isLocalOrTarget) {
      egress.add(domain);
    }
  }

  notes.push(`Integrity: parsed ${scripts.length} script(s), found ${egress.size} egress domain(s).`);

  return {
    scripts,
    egress: Array.from(egress),
    notes,
  };
}

/**
 * Compares current scripts & egress domains against baseline behavioral signals,
 * generating CRITICAL findings for unauthorized changes.
 */
export function diffIntegrity(
  currentScripts: ScriptSignal[],
  currentEgress: string[],
  baseline: BehaviorBaseline,
  pageUrl: string,
): { findings: ScanFinding[]; notes: string[] } {
  const findings: ScanFinding[] = [];
  const notes: string[] = [];

  const baselineScripts = baseline.scripts ?? [];
  const baselineEgress = new Set(baseline.egress ?? []);

  // 1. Diff Scripts
  // Map baseline scripts by src (for external) or hash (for inline)
  const baseExternals = new Map<string, string>(); // src -> sha256
  const baseInlines = new Set<string>(); // sha256

  baselineScripts.forEach((s) => {
    if (s.src) {
      baseExternals.set(s.src, s.sha256);
    } else {
      baseInlines.add(s.sha256);
    }
  });

  currentScripts.forEach((s) => {
    if (s.src) {
      const baseHash = baseExternals.get(s.src);
      if (baseHash === undefined) {
        // Brand new external script origin/file
        findings.push({
          id: `integrity-new-script-${sha256(s.src).slice(0, 8)}`,
          category: "SUPPLY_CHAIN",
          risk: "critical",
          title: "New external script source injected",
          detail: `A new external script source was detected that was not in the baseline: ${s.src}. This is a high-confidence indicator of potential supply-chain compromise or malicious DOM injection (e.g., credit card skimmers).`,
          remediation: "Audit your application codebase or CDN settings to verify this script is authorized. Implement a strict Content Security Policy (CSP).",
          evidence: `src=${s.src} sha256=${s.sha256}`,
          owasp: "A08:2021 Software and Data Integrity Failures",
          cwe: "CWE-829",
          url: pageUrl,
        });
      } else if (baseHash !== s.sha256) {
        // Script content was modified
        findings.push({
          id: `integrity-modified-script-${sha256(s.src).slice(0, 8)}`,
          category: "SUPPLY_CHAIN",
          risk: "critical",
          title: "External script content modified (hash mismatch)",
          detail: `An existing external script has changed its content compared to the baseline: ${s.src}. Original SHA-256: ${baseHash.slice(0, 10)}... Current SHA-256: ${s.sha256.slice(0, 10)}... This indicates the script was modified at the source or tampered with on the network.`,
          remediation: "Verify the script updates with the vendor. Force Subresource Integrity (SRI) hashes on all external script elements.",
          evidence: `src=${s.src} expected_sha=${baseHash} actual_sha=${s.sha256}`,
          owasp: "A08:2021 Software and Data Integrity Failures",
          cwe: "CWE-353",
          url: pageUrl,
        });
      }
    } else {
      // Inline script
      if (!baseInlines.has(s.sha256)) {
        findings.push({
          id: `integrity-new-inline-${s.sha256.slice(0, 8)}`,
          category: "SUPPLY_CHAIN",
          risk: "critical",
          title: "New inline script block detected",
          detail: `A brand-new inline script block was detected that was not present in your baseline (SHA-256: ${s.sha256}). Inline injections are typical payloads for XSS-based card skimmers (Magecart) or adware.`,
          remediation: "Verify whether this inline script block is a result of a recent deployment. Refactor to external scripts and block inline execution using CSP 'unsafe-inline' restrictions.",
          evidence: `sha256=${s.sha256}`,
          owasp: "A03:2021 Injection",
          cwe: "CWE-79",
          url: pageUrl,
        });
      }
    }
  });

  // 2. Diff Egress Outbound Domains
  currentEgress.forEach((domain) => {
    if (!baselineEgress.has(domain)) {
      findings.push({
        id: `integrity-new-egress-${sha256(domain).slice(0, 8)}`,
        category: "SUPPLY_CHAIN",
        risk: "critical",
        title: "New outbound egress domain detected (Exfil Risk)",
        detail: `A new external outbound domain was discovered in the page HTML: ${domain}. Brand-new egress destinations represent an extremely high exfiltration risk (e.g. credit card data skimmers posting back to receiver gates).`,
        remediation: "Review scripts and resource links to find what is initiating connections to this domain. Implement a strict CSP connect-src header.",
        evidence: `domain=${domain}`,
        owasp: "A05:2021 Security Misconfiguration",
        cwe: "CWE-1021",
        url: pageUrl,
      });
      notes.push(`Integrity alert: new outbound domain ${domain} flagged.`);
    }
  });

  return {
    findings,
    notes,
  };
}
