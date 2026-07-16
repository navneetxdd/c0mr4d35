/**
 * Shodan + InternetDB recon.
 * - InternetDB (https://internetdb.shodan.io/{ip}) is keyless and returns ports,
 *   vulns, and known hostnames for an IP.
 * - Full Shodan REST (BYOK) unlocks /shodan/host/{ip} banners and
 *   /dns/domain/{domain} subdomain enumeration.
 */

import type { ScanFinding } from "./risk";

const INTERNETDB = "https://internetdb.shodan.io";
const SHODAN_API = "https://api.shodan.io";

export interface InternetDbRecord {
  ip: string;
  ports: number[];
  vulns: string[];
  hostnames: string[];
  cpes: string[];
  tags: string[];
}

export interface ShodanHostRecord {
  ip: string;
  ports: number[];
  vulns: string[];
  hostnames: string[];
  org: string | null;
  isp: string | null;
  os: string | null;
}

export interface ShodanDomainRecord {
  domain: string;
  subdomains: string[];
  notes: string[];
}

async function fetchJson<T>(url: string, timeoutMs: number): Promise<{ ok: true; data: T } | { ok: false; error: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { accept: "application/json", "user-agent": "DatumScanner/1.0" },
    });
    if (res.status === 404) return { ok: false, error: "not found" };
    // 401 = bad/missing key. 403 is usually a valid key without Membership for paid endpoints.
    if (res.status === 401) return { ok: false, error: "invalid API key" };
    if (res.status === 403) {
      return {
        ok: false,
        error:
          "access denied (Shodan Membership required for api.shodan.io — free keys work for account/info; InternetDB still runs without a key)",
      };
    }
    if (res.status === 429) return { ok: false, error: "rate limited" };
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    const data = (await res.json()) as T;
    return { ok: true, data };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : "request failed",
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function lookupInternetDb(ip: string): Promise<{
  record: InternetDbRecord | null;
  notes: string[];
  findings: ScanFinding[];
}> {
  const notes: string[] = [];
  const findings: ScanFinding[] = [];
  if (!ip || ip.includes(":")) {
    notes.push("InternetDB skipped (IPv6 or empty address).");
    return { record: null, notes, findings };
  }

  const result = await fetchJson<{
    ip?: string | number;
    ports?: number[];
    vulns?: string[];
    hostnames?: string[];
    cpes?: string[];
    tags?: string[];
  }>(`${INTERNETDB}/${encodeURIComponent(ip)}`, 8_000);

  if (!result.ok) {
    notes.push(`InternetDB: ${result.error}`);
    return { record: null, notes, findings };
  }

  const record: InternetDbRecord = {
    ip: String(result.data.ip ?? ip),
    ports: Array.isArray(result.data.ports) ? result.data.ports.filter((p) => Number.isInteger(p)) : [],
    vulns: Array.isArray(result.data.vulns) ? result.data.vulns.map(String) : [],
    hostnames: Array.isArray(result.data.hostnames) ? result.data.hostnames.map((h) => h.toLowerCase()) : [],
    cpes: Array.isArray(result.data.cpes) ? result.data.cpes.map(String) : [],
    tags: Array.isArray(result.data.tags) ? result.data.tags.map(String) : [],
  };

  notes.push(
    `InternetDB: ${record.ports.length} port(s), ${record.vulns.length} vuln id(s), ${record.hostnames.length} hostname(s) for ${record.ip}.`,
  );

  for (const cve of record.vulns.slice(0, 12)) {
    findings.push({
      id: `shodan-internetdb-${cve.toLowerCase()}`,
      category: "CVE",
      risk: "high",
      title: `Shodan InternetDB reports ${cve}`,
      detail: `InternetDB associates ${cve} with ${record.ip}. Corroborate against your stack before treating as confirmed exploitability.`,
      remediation: "Patch or mitigate the affected service; verify with vendor advisory.",
      evidence: `ip=${record.ip} cve=${cve} ports=${record.ports.join(",")}`,
      reference: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`,
      owasp: "A06:2021 Vulnerable and Outdated Components",
      cwe: "CWE-1035",
      url: `https://${record.ip}`,
    });
  }

  return { record, notes, findings };
}

export async function lookupShodanHost(
  ip: string,
  apiKey: string,
): Promise<{ record: ShodanHostRecord | null; notes: string[]; findings: ScanFinding[] }> {
  const notes: string[] = [];
  const findings: ScanFinding[] = [];
  const key = apiKey.trim();
  if (!key) return { record: null, notes: ["Shodan host lookup skipped (no key)."], findings };
  if (!ip || ip.includes(":")) {
    return { record: null, notes: ["Shodan host lookup skipped (IPv6 or empty)."], findings };
  }

  const url = `${SHODAN_API}/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(key)}&minify=true`;
  const result = await fetchJson<{
    ip_str?: string;
    ports?: number[];
    vulns?: string[] | Record<string, unknown>;
    hostnames?: string[];
    org?: string;
    isp?: string;
    os?: string;
  }>(url, 12_000);

  // #region agent log
  fetch("http://127.0.0.1:7781/ingest/1e3609e4-83e2-4af4-abe1-9c10d5bd2172", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "749116" },
    body: JSON.stringify({
      sessionId: "749116",
      runId: "byok-fix",
      hypothesisId: "H-shodan",
      location: "shodan.ts:lookupShodanHost",
      message: "shodan host result",
      data: { ok: result.ok, error: result.ok ? null : result.error, keyLen: key.length },
      timestamp: Date.now(),
    }),
  }).catch(() => {});
  // #endregion

  if (!result.ok) {
    notes.push(`Shodan host: ${result.error}`);
    return { record: null, notes, findings };
  }

  const vulnsRaw = result.data.vulns;
  const vulns = Array.isArray(vulnsRaw)
    ? vulnsRaw.map(String)
    : vulnsRaw && typeof vulnsRaw === "object"
      ? Object.keys(vulnsRaw)
      : [];

  const record: ShodanHostRecord = {
    ip: result.data.ip_str ?? ip,
    ports: Array.isArray(result.data.ports) ? result.data.ports.filter((p) => Number.isInteger(p)) : [],
    vulns,
    hostnames: Array.isArray(result.data.hostnames)
      ? result.data.hostnames.map((h) => h.toLowerCase())
      : [],
    org: result.data.org ?? null,
    isp: result.data.isp ?? null,
    os: result.data.os ?? null,
  };

  notes.push(
    `Shodan host: ${record.ports.length} port(s), ${record.vulns.length} vuln(s)${record.org ? `, org=${record.org}` : ""}.`,
  );

  for (const cve of record.vulns.slice(0, 15)) {
    findings.push({
      id: `shodan-host-${cve.toLowerCase()}`,
      category: "CVE",
      risk: "high",
      title: `Shodan indexes ${cve} on this host`,
      detail: `Shodan host lookup for ${record.ip} lists ${cve}. Confirm applicability to exposed services.`,
      remediation: "Review Shodan banner evidence and apply vendor patches.",
      evidence: `ip=${record.ip} cve=${cve} ports=${record.ports.join(",")}`,
      reference: `https://www.shodan.io/host/${encodeURIComponent(record.ip)}`,
      owasp: "A06:2021 Vulnerable and Outdated Components",
      url: `https://${record.ip}`,
    });
  }

  return { record, notes, findings };
}

export async function lookupShodanDomain(
  domain: string,
  apiKey: string,
): Promise<ShodanDomainRecord> {
  const notes: string[] = [];
  const key = apiKey.trim();
  if (!key) {
    return { domain, subdomains: [], notes: ["Shodan DNS domain skipped (no key)."] };
  }

  const url = `${SHODAN_API}/dns/domain/${encodeURIComponent(domain)}?key=${encodeURIComponent(key)}`;
  const result = await fetchJson<{
    domain?: string;
    subdomains?: string[];
    data?: Array<{ subdomain?: string; type?: string; value?: string }>;
  }>(url, 12_000);

  if (!result.ok) {
    notes.push(`Shodan DNS domain: ${result.error}`);
    return { domain, subdomains: [], notes };
  }

  const names = new Set<string>();
  for (const sub of result.data.subdomains ?? []) {
    const full = sub.includes(".") ? sub.toLowerCase() : `${sub.toLowerCase()}.${domain}`;
    if (full.endsWith(domain)) names.add(full);
  }
  for (const row of result.data.data ?? []) {
    if (row.subdomain) {
      const full = `${row.subdomain.toLowerCase()}.${domain}`;
      names.add(full);
    }
  }

  notes.push(`Shodan DNS: ${names.size} subdomain name(s) for ${domain}.`);
  return { domain, subdomains: [...names], notes };
}
