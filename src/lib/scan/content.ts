import type { ResolvedTarget } from "./ssrf";
import { fetchWithPin } from "./client";
import type { ScanFinding } from "./risk";

/**
 * Passive HTML content analysis of a single page: mixed content, missing
 * Subresource Integrity, forms posting over cleartext, and exposed JS source
 * maps. Also extracts behavioral signals (external script origins, form
 * targets) used for cross-scan change detection.
 */

export interface ContentSignals {
  externalScriptOrigins: string[];
  formActions: string[];
  hasPasswordInput: boolean;
}

const TAG_SRC = /<(script|iframe|link|img)\b[^>]*?\b(src|href)=["']([^"']+)["'][^>]*>/gi;
const SCRIPT_TAG = /<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi;
const FORM_TAG = /<form\b[^>]*\baction=["']([^"']+)["'][^>]*>/gi;
const SOURCEMAP = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/gi;

function abs(href: string, base: string): URL | null {
  try {
    return new URL(href, base);
  } catch {
    return null;
  }
}

export function extractSignals(html: string, pageUrl: string): ContentSignals {
  const origin = new URL(pageUrl).origin;
  const scriptOrigins = new Set<string>();
  let m: RegExpExecArray | null;

  SCRIPT_TAG.lastIndex = 0;
  while ((m = SCRIPT_TAG.exec(html)) !== null) {
    const u = abs(m[1]!, pageUrl);
    if (u && u.origin !== origin) scriptOrigins.add(u.origin);
  }

  const formActions = new Set<string>();
  FORM_TAG.lastIndex = 0;
  while ((m = FORM_TAG.exec(html)) !== null) {
    const u = abs(m[1]!, pageUrl);
    if (u) formActions.add(u.toString());
  }

  return {
    externalScriptOrigins: [...scriptOrigins],
    formActions: [...formActions],
    hasPasswordInput: /<input\b[^>]*type=["']password["']/i.test(html),
  };
}

export async function analyzeContent(
  html: string,
  pageUrl: string,
  pin: ResolvedTarget,
): Promise<ScanFinding[]> {
  const out: ScanFinding[] = [];
  const isHttps = new URL(pageUrl).protocol === "https:";
  const origin = new URL(pageUrl).origin;

  // 1. Mixed content (only meaningful on https pages).
  if (isHttps) {
    let activeMixed = 0;
    let passiveMixed = 0;
    let m: RegExpExecArray | null;
    TAG_SRC.lastIndex = 0;
    while ((m = TAG_SRC.exec(html)) !== null) {
      const tag = m[1]!.toLowerCase();
      const val = m[3]!;
      if (/^http:\/\//i.test(val)) {
        if (tag === "img") passiveMixed += 1;
        else activeMixed += 1;
      }
    }
    if (activeMixed > 0) {
      out.push({
        id: "mixed-active",
        category: "CONTENT",
        risk: "medium",
        title: "Active mixed content over HTTP",
        detail: `${activeMixed} script/iframe/stylesheet resource(s) load over cleartext http:// on an https page, exposing them to tampering.`,
        remediation: "Serve all subresources over https, or use protocol-relative/https URLs.",
        owasp: "A05:2021 Security Misconfiguration",
        cwe: "CWE-311",
        url: pageUrl,
      });
    }
    if (passiveMixed > 0) {
      out.push({
        id: "mixed-passive",
        category: "CONTENT",
        risk: "low",
        title: "Passive mixed content over HTTP",
        detail: `${passiveMixed} image(s) load over cleartext http:// on an https page.`,
        remediation: "Serve images over https to avoid mixed-content warnings and tampering.",
        owasp: "A05:2021 Security Misconfiguration",
        cwe: "CWE-311",
        url: pageUrl,
      });
    }
  }

  // 2. Missing Subresource Integrity on cross-origin scripts.
  {
    let missingSri = 0;
    let m: RegExpExecArray | null;
    SCRIPT_TAG.lastIndex = 0;
    while ((m = SCRIPT_TAG.exec(html)) !== null) {
      const full = m[0];
      const u = abs(m[1]!, pageUrl);
      if (u && u.origin !== origin && !/\bintegrity=/i.test(full)) missingSri += 1;
    }
    if (missingSri > 0) {
      out.push({
        id: "missing-sri",
        category: "CONTENT",
        risk: "low",
        title: "Third-party scripts without Subresource Integrity",
        detail: `${missingSri} cross-origin <script> tag(s) lack an integrity attribute; a compromised CDN could serve malicious code undetected.`,
        remediation: "Add integrity + crossorigin attributes (SRI hashes) to third-party scripts.",
        owasp: "A08:2021 Software and Data Integrity Failures",
        cwe: "CWE-353",
        url: pageUrl,
      });
    }
  }

  // 3. Forms posting over cleartext / credential exposure.
  {
    let m: RegExpExecArray | null;
    FORM_TAG.lastIndex = 0;
    const hasPassword = /<input\b[^>]*type=["']password["']/i.test(html);
    while ((m = FORM_TAG.exec(html)) !== null) {
      const u = abs(m[1]!, pageUrl);
      if (u && u.protocol === "http:") {
        out.push({
          id: "form-cleartext",
          category: "CONTENT",
          risk: hasPassword ? "high" : "medium",
          title: hasPassword ? "Login form submits over cleartext HTTP" : "Form submits over cleartext HTTP",
          detail: `A form posts to ${u.origin} over http://${hasPassword ? ", and the page contains a password field — credentials would be sent in cleartext" : ""}.`,
          remediation: "Point all form actions at https endpoints; never submit credentials over http.",
          evidence: `action=${u.toString().slice(0, 120)}`,
          owasp: "A02:2021 Cryptographic Failures",
          cwe: "CWE-319",
          url: pageUrl,
        });
        break; // one finding per page is enough
      }
    }
  }

  // 4. Exposed JS source maps (verify up to 2 to keep it high-confidence).
  {
    const maps: string[] = [];
    let m: RegExpExecArray | null;
    SOURCEMAP.lastIndex = 0;
    while ((m = SOURCEMAP.exec(html)) !== null && maps.length < 2) {
      const u = abs(m[1]!, pageUrl);
      if (u && u.origin === origin && /\.map$/.test(u.pathname)) maps.push(u.toString());
    }
    for (const mapUrl of maps) {
      try {
        const res = await fetchWithPin(mapUrl, pin, { timeoutMs: 5000, maxBytes: 4000 });
        if (res.status >= 200 && res.status < 300 && /"sources"|"mappings"/.test(res.body)) {
          out.push({
            id: "sourcemap-exposed",
            category: "CONTENT",
            risk: "low",
            title: "JavaScript source map publicly accessible",
            detail: "A .map file is reachable, exposing original source and structure that aids reverse engineering.",
            remediation: "Do not deploy source maps to production, or restrict access to them.",
            evidence: mapUrl.slice(0, 120),
            owasp: "A05:2021 Security Misconfiguration",
            cwe: "CWE-540",
            url: pageUrl,
          });
          break;
        }
      } catch {
        // ignore
      }
    }
  }

  return out;
}
