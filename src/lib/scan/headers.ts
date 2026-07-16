import type { ScanFinding } from "./risk";

/**
 * Security-header posture audit. Missing hardening headers are real,
 * demonstrable findings on the monitored site (not on our own app).
 */

interface HeaderRule {
  header: string;
  category: "HEADERS";
  risk: ScanFinding["risk"];
  title: string;
  remediation: string;
  // Optional predicate: present but weak still counts.
  weak?: (value: string) => string | null;
}

const RULES: HeaderRule[] = [
  {
    header: "content-security-policy",
    category: "HEADERS",
    risk: "high",
    title: "Content-Security-Policy missing",
    remediation: "Add a restrictive CSP; begin in report-only, then enforce default-src 'self'.",
    weak: (v) => (/unsafe-inline|unsafe-eval|\*/.test(v) ? "CSP present but permissive (unsafe-inline/eval or wildcard)" : null),
  },
  {
    header: "strict-transport-security",
    category: "HEADERS",
    risk: "medium",
    title: "Strict-Transport-Security missing",
    remediation: "Send HSTS with max-age>=15552000 and includeSubDomains.",
    weak: (v) => (/max-age=0|max-age=[1-9]\d{0,4}\b/.test(v) ? "HSTS max-age is too short" : null),
  },
  {
    header: "x-frame-options",
    category: "HEADERS",
    risk: "medium",
    title: "X-Frame-Options / frame-ancestors missing",
    remediation: "Set X-Frame-Options: DENY or CSP frame-ancestors 'none' to prevent clickjacking.",
  },
  {
    header: "x-content-type-options",
    category: "HEADERS",
    risk: "low",
    title: "X-Content-Type-Options missing",
    remediation: "Set X-Content-Type-Options: nosniff.",
  },
  {
    header: "referrer-policy",
    category: "HEADERS",
    risk: "low",
    title: "Referrer-Policy missing",
    remediation: "Set Referrer-Policy: strict-origin-when-cross-origin.",
  },
  {
    header: "permissions-policy",
    category: "HEADERS",
    risk: "low",
    title: "Permissions-Policy missing",
    remediation: "Set a Permissions-Policy to restrict powerful features (camera, geolocation, etc.).",
  },
];

const HEADER_CWE: Record<string, string> = {
  "content-security-policy": "CWE-1021",
  "strict-transport-security": "CWE-319",
  "x-frame-options": "CWE-1021",
  "x-content-type-options": "CWE-693",
  "referrer-policy": "CWE-200",
  "permissions-policy": "CWE-693",
};

export function auditHeaders(headers: Record<string, string>, pageUrl?: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const cspPresent = Boolean(headers["content-security-policy"]);
  const owasp = "A05:2021 Security Misconfiguration";

  for (const rule of RULES) {
    // frame-ancestors in CSP satisfies the X-Frame-Options rule.
    if (
      rule.header === "x-frame-options" &&
      cspPresent &&
      /frame-ancestors/.test(headers["content-security-policy"] ?? "")
    ) {
      continue;
    }

    const value = headers[rule.header];
    if (!value) {
      findings.push({
        id: `hdr-${rule.header}`,
        category: rule.category,
        risk: rule.risk,
        title: rule.title,
        detail: `Response did not include the ${rule.header} header.`,
        remediation: rule.remediation,
        owasp,
        cwe: HEADER_CWE[rule.header],
        url: pageUrl,
      });
      continue;
    }
    const weakness = rule.weak?.(value);
    if (weakness) {
      findings.push({
        id: `hdr-${rule.header}-weak`,
        category: rule.category,
        risk: "low",
        title: `${rule.title.replace(" missing", "")} weak configuration`,
        detail: weakness,
        remediation: rule.remediation,
        evidence: `${rule.header}: ${value.slice(0, 180)}`,
        owasp,
        cwe: HEADER_CWE[rule.header],
        url: pageUrl,
      });
    }
  }

  // Server/version disclosure is an info-level hygiene finding.
  const disclosure = ["server", "x-powered-by"].filter((h) => headers[h] && /\d/.test(headers[h]!));
  for (const h of disclosure) {
    findings.push({
      id: `hdr-disclosure-${h}`,
      category: "HEADERS",
      risk: "info",
      title: `Technology/version disclosure via ${h}`,
      detail: `Header reveals stack detail: ${headers[h]}`,
      remediation: `Suppress or genericize the ${h} header.`,
      evidence: `${h}: ${headers[h]}`,
      owasp,
      cwe: "CWE-200",
      url: pageUrl,
    });
  }

  return findings;
}
