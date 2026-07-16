import type { ScanFinding } from "./risk";

/**
 * Cookie security-attribute audit. Parses Set-Cookie headers and flags session
 * cookies missing Secure / HttpOnly / SameSite. Evidence-based: we only flag
 * cookies the server actually set.
 */

// Node lowercases and joins multiple Set-Cookie with ", " which is ambiguous
// (dates contain commas). We split on the boundary between "; ..., name=" pairs.
function splitSetCookie(raw: string): string[] {
  if (!raw) return [];
  return raw
    .split(/,(?=\s*[A-Za-z0-9!#$%&'*+._-]+=)/)
    .map((c) => c.trim())
    .filter(Boolean);
}

const SESSION_HINT = /(sess|sid|auth|token|jwt|login|remember|csrf)/i;

export function auditCookies(setCookie: string | undefined, isHttps: boolean, pageUrl: string): ScanFinding[] {
  const cookies = splitSetCookie(setCookie ?? "");
  if (!cookies.length) return [];
  const out: ScanFinding[] = [];

  for (const c of cookies) {
    const name = c.split("=")[0]?.trim() ?? "cookie";
    const lower = c.toLowerCase();
    const hasSecure = /;\s*secure(\s*;|\s*$)/.test(lower) || lower.includes("; secure");
    const hasHttpOnly = lower.includes("httponly");
    const hasSameSite = lower.includes("samesite");
    const looksSession = SESSION_HINT.test(name);
    const risk = looksSession ? "medium" : "low";
    const gaps: string[] = [];
    if (isHttps && !hasSecure) gaps.push("Secure");
    if (!hasHttpOnly) gaps.push("HttpOnly");
    if (!hasSameSite) gaps.push("SameSite");
    if (!gaps.length) continue;

    out.push({
      id: `cookie-${name}-${gaps.join("-").toLowerCase()}`,
      category: "COOKIES",
      risk,
      title: `Cookie "${name}" missing ${gaps.join(", ")}`,
      detail: `The cookie "${name}" was set without ${gaps.join(", ")}${looksSession ? " and its name suggests a session/auth cookie" : ""}.`,
      remediation: `Set ${gaps.join(", ")} on "${name}". Session cookies should be Secure; HttpOnly; SameSite=Lax or Strict.`,
      evidence: c.slice(0, 120),
      owasp: "A05:2021 Security Misconfiguration",
      cwe: gaps.includes("HttpOnly") ? "CWE-1004" : "CWE-614",
      url: pageUrl,
    });
  }

  return out;
}
