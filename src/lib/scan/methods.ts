import type { ResolvedTarget } from "./ssrf";
import { fetchWithPin } from "./client";
import type { ScanFinding } from "./risk";

/**
 * HTTP method exposure. A single OPTIONS request reveals the server's advertised
 * Allow set. Dangerous methods (TRACE, PUT, DELETE, CONNECT) enabled on a
 * public origin are a misconfiguration. Passive — OPTIONS is non-mutating.
 */

const DANGEROUS = ["TRACE", "TRACK", "PUT", "DELETE", "CONNECT", "PATCH"];

export async function checkMethods(url: string, pin: ResolvedTarget): Promise<ScanFinding[]> {
  let res;
  try {
    res = await fetchWithPin(url, pin, { method: "OPTIONS", timeoutMs: 6000, maxBytes: 2000 });
  } catch {
    return [];
  }

  const allow = (res.headers["allow"] ?? res.headers["access-control-allow-methods"] ?? "").toUpperCase();
  if (!allow) return [];

  const enabled = DANGEROUS.filter((mth) => new RegExp(`\\b${mth}\\b`).test(allow));
  if (!enabled.length) return [];

  const hasTrace = enabled.includes("TRACE") || enabled.includes("TRACK");
  return [
    {
      id: `methods-${enabled.join("-").toLowerCase()}`,
      category: "METHODS",
      risk: hasTrace ? "medium" : "low",
      title: `Risky HTTP methods enabled: ${enabled.join(", ")}`,
      detail: `The server advertises ${enabled.join(", ")} via OPTIONS.${hasTrace ? " TRACE/TRACK can enable Cross-Site Tracing (XST)." : " Write methods should not be publicly reachable without auth."}`,
      remediation: "Disable unused methods at the web server/proxy; restrict write methods to authenticated APIs.",
      evidence: `Allow: ${allow.slice(0, 120)}`,
      owasp: "A05:2021 Security Misconfiguration",
      cwe: "CWE-16",
      url,
    },
  ];
}
