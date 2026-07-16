import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import type { ScanFinding } from "./risk";
import { lookupShodanDomain } from "./shodan";

export interface SubdomainResult {
  subdomain: string;
  source: "ct" | "shodan" | "internetdb";
  ips: string[];
  queriedAt: string;
}

function registrableDomain(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  const parts = host.split(".").filter(Boolean);
  if (parts.length <= 2) return host;
  const multi = new Set(["co.uk", "org.uk", "ac.uk", "com.au", "co.in", "com.br"]);
  const lastTwo = parts.slice(-2).join(".");
  const lastThree = parts.slice(-3).join(".");
  if (parts.length >= 3 && multi.has(lastTwo)) return lastThree;
  return lastTwo;
}

async function fetchCtNames(domain: string): Promise<{ names: string[]; note: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { accept: "application/json", "user-agent": "DatumScanner/1.0" },
    });
    if (!res.ok) return { names: [], note: `Certificate Transparency HTTP ${res.status}.` };
    const text = await res.text();
    if (text.length > 2_500_000) {
      return { names: [], note: "Certificate Transparency response too large; skipped." };
    }
    const rows = JSON.parse(text) as Array<{ name_value?: string }>;
    const names = new Set<string>();
    for (const row of rows) {
      const raw = row.name_value ?? "";
      for (const line of raw.split(/\n+/)) {
        const name = line.trim().toLowerCase().replace(/^\*\./, "");
        if (!name || name.includes(" ")) continue;
        if (name !== domain && !name.endsWith(`.${domain}`)) continue;
        if (name === domain) continue;
        names.add(name);
        if (names.size >= 120) break;
      }
      if (names.size >= 120) break;
    }
    return {
      names: [...names],
      note: `Certificate Transparency (crt.sh) returned ${names.size} unique name(s) for %.${domain}.`,
    };
  } catch {
    return { names: [], note: `Certificate Transparency timed out or failed for %.${domain}.` };
  } finally {
    clearTimeout(timer);
  }
}

async function resolveHost(name: string): Promise<string[]> {
  try {
    const records = await Promise.race([
      lookup(name, { all: true }),
      new Promise<never>((_, rej) => setTimeout(() => rej(new Error("dns-timeout")), 2_500)),
    ]);
    return records.map((r) => r.address);
  } catch {
    return [];
  }
}

async function mapPool<T, R>(items: T[], concurrency: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  let i = 0;
  async function worker() {
    while (i < items.length) {
      const idx = i++;
      const item = items[idx];
      if (item === undefined) return;
      out[idx] = await fn(item);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length || 1) }, () => worker()));
  return out;
}

export async function discoverSubdomains(
  hostname: string,
  opts?: { shodanApiKey?: string | null; extraHostnames?: string[] },
): Promise<{ results: SubdomainResult[]; findings: ScanFinding[]; notes: string[] }> {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (isIP(host)) {
    return {
      results: [],
      findings: [],
      notes: ["Subdomain discovery skipped — target is an IP address, not a DNS name."],
    };
  }

  const domain = registrableDomain(host);
  // Guard against garbage registrable labels (e.g. accidental IP fragment paths).
  if (!domain.includes(".") || /^\d+$/.test(domain.split(".")[0] ?? "")) {
    return {
      results: [],
      findings: [],
      notes: ["Subdomain discovery skipped — hostname is not a registrable DNS domain."],
    };
  }

  const notes: string[] = [];
  const findings: ScanFinding[] = [];
  const queriedAt = new Date().toISOString();
  const candidates = new Map<string, SubdomainResult["source"]>();

  const ct = await fetchCtNames(domain);
  notes.push(ct.note);
  for (const name of ct.names) candidates.set(name, "ct");

  if (opts?.shodanApiKey?.trim()) {
    const shodanDns = await lookupShodanDomain(domain, opts.shodanApiKey);
    notes.push(...shodanDns.notes);
    for (const name of shodanDns.subdomains) {
      if (!candidates.has(name)) candidates.set(name, "shodan");
    }
  } else {
    notes.push(
      "Shodan DNS domain skipped — add a Shodan API key in Settings for indexed subdomain enumeration.",
    );
  }

  for (const host of opts?.extraHostnames ?? []) {
    const name = host.toLowerCase();
    if (name === domain || name.endsWith(`.${domain}`)) {
      if (!candidates.has(name) && name !== domain) candidates.set(name, "internetdb");
    }
  }

  const entries = [...candidates.entries()];
  const resolved = await mapPool(entries, 10, async ([name, source]) => {
    const ips = await resolveHost(name);
    return { subdomain: name, source, ips, queriedAt } satisfies SubdomainResult;
  });

  const results = resolved
    .filter((r): r is SubdomainResult => Boolean(r))
    .sort((a, b) => a.subdomain.localeCompare(b.subdomain));

  const withIps = results.filter((r) => r.ips.length > 0);
  notes.push(
    `Subdomain discovery: ${results.length} observed name(s) from CT/Shodan/InternetDB; ${withIps.length} currently resolve.`,
  );

  return { results, findings, notes };
}

export function subdomainChangeFindings(
  previous: string[] | null | undefined,
  current: SubdomainResult[],
): ScanFinding[] {
  if (!previous?.length) return [];
  const prev = new Set(previous.map((s) => s.toLowerCase()));
  const now = current.map((r) => r.subdomain.toLowerCase());
  const added = now.filter((s) => !prev.has(s));
  if (!added.length) return [];
  return [
    {
      id: "subdomain-set-expanded",
      category: "SUBDOMAINS",
      risk: "medium",
      title: "New subdomains since baseline",
      detail: `${added.length} subdomain(s) appeared that were not in the stored baseline: ${added.slice(0, 8).join(", ")}.`,
      remediation: "Confirm new hostnames are intentional; unexpected names can indicate shadow IT or takeover risk.",
      evidence: `added=${added.slice(0, 12).join(",")} previousCount=${prev.size}`,
      owasp: "A05:2021 Security Misconfiguration",
    },
  ];
}
