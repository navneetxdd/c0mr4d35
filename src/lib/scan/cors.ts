import type { ResolvedTarget } from "./ssrf";
import { fetchWithPin } from "./client";
import type { ScanFinding } from "./risk";

/**
 * CORS misconfiguration probe. Sends a benign GET with a foreign Origin and
 * inspects the reflection. This is passive (a normal GET with one extra header)
 * — no state change on the target.
 *
 *   - reflects arbitrary Origin AND allows credentials  => critical (any site
 *     can read authenticated responses)
 *   - reflects arbitrary Origin (no credentials)        => medium
 *   - Access-Control-Allow-Origin: *  with credentials  => high (invalid combo,
 *     but some stacks mishandle it)
 */

const PROBE_ORIGIN = "https://cors-probe.example.com";

export async function probeCors(url: string, pin: ResolvedTarget): Promise<ScanFinding[]> {
  let res;
  try {
    res = await fetchWithPin(url, pin, {
      timeoutMs: 6000,
      maxBytes: 4000,
      headers: { origin: PROBE_ORIGIN },
    });
  } catch {
    return [];
  }

  const acao = res.headers["access-control-allow-origin"];
  const acac = (res.headers["access-control-allow-credentials"] ?? "").toLowerCase() === "true";
  if (!acao) return [];

  const reflects = acao === PROBE_ORIGIN;
  const wildcard = acao === "*";

  if (reflects && acac) {
    return [
      {
        id: "cors-reflect-credentials",
        category: "CORS",
        risk: "critical",
        title: "CORS reflects arbitrary origin with credentials",
        detail: "The server echoes any Origin in Access-Control-Allow-Origin while allowing credentials, so any website can read authenticated responses on behalf of a logged-in user.",
        remediation: "Never reflect the Origin with credentials enabled. Allow-list exact trusted origins; drop Access-Control-Allow-Credentials unless required.",
        evidence: `ACAO: ${acao}; ACAC: true`,
        owasp: "A05:2021 Security Misconfiguration",
        cwe: "CWE-942",
        url,
      },
    ];
  }
  if (reflects) {
    return [
      {
        id: "cors-reflect",
        category: "CORS",
        risk: "medium",
        title: "CORS reflects arbitrary origin",
        detail: "The server echoes any supplied Origin in Access-Control-Allow-Origin. Cross-origin sites can read non-credentialed responses.",
        remediation: "Restrict Access-Control-Allow-Origin to an explicit allow-list of trusted origins.",
        evidence: `ACAO: ${acao}`,
        owasp: "A05:2021 Security Misconfiguration",
        cwe: "CWE-942",
        url,
      },
    ];
  }
  if (wildcard && acac) {
    return [
      {
        id: "cors-wildcard-credentials",
        category: "CORS",
        risk: "high",
        title: "CORS wildcard origin combined with credentials",
        detail: "Access-Control-Allow-Origin is '*' while credentials are allowed — an invalid, dangerous combination that some clients still honor.",
        remediation: "Do not combine a wildcard origin with credentials. Use an explicit origin allow-list.",
        evidence: `ACAO: *; ACAC: true`,
        owasp: "A05:2021 Security Misconfiguration",
        cwe: "CWE-942",
        url,
      },
    ];
  }
  return [];
}
