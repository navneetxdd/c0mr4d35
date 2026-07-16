import { lookup } from "node:dns/promises";
import type { ScanFinding } from "./risk";

const PREFIX_WORDLIST = [
  "www",
  "mail",
  "api",
  "dev",
  "staging",
  "cdn",
  "app",
  "admin",
  "portal",
  "blog",
  "shop",
  "m",
  "vpn",
  "git",
  "status",
  "docs",
  "test",
  "beta",
] as const;

export interface SubdomainResult {
  subdomain: string;
  source: "ct" | "wordlist";
  ips: string[];
  queriedAt: string;
}

function registrableDomain(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  const parts = host.split(".").filter(Boolean);
  if (parts.length <= 2) return host;
  return parts.slice(-2).join(".");
}

async function fetchCtNames(domain: string): Promise<string[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6_000);
  try {
    const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { accept: "application/json", "user-agent": "DatumScanner/1.0" },
    });
    if (!res.ok) return [];
    const text = await res.text();
    if (text.length > 1_500_000) return [];
    const rows = JSON.parse(text) as Array<{ name_value?: string }>;
    const names = new Set<string>();
    for (const row of rows.slice(0, 200)) {
      const raw = row.name_value ?? "";
      for (const line of raw.split(/\n+/)) {
        const name = line.trim().toLowerCase().replace(/^\*\./, "");
        if (!name || name.includes(" ") || !name.endsWith(domain)) continue;
        names.add(name);
        if (names.size >= 25) break;
      }
      if (names.size >= 25) break;
    }
    return [...names];
  } catch {
    return [];
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
): Promise<{ results: SubdomainResult[]; findings: ScanFinding[]; notes: string[] }> {
  const domain = registrableDomain(hostname);
  const notes: string[] = [];
  const queriedAt = new Date().toISOString();
  const candidates = new Map<string, "ct" | "wordlist">();

  const ctNames = await fetchCtNames(domain);
  notes.push(
    ctNames.length
      ? `Certificate Transparency returned ${ctNames.length} name(s) for %.${domain}.`
      : `Certificate Transparency returned no usable names for %.${domain} (or timed out).`,
  );
  for (const name of ctNames) candidates.set(name, "ct");
  for (const prefix of PREFIX_WORDLIST) {
    const name = `${prefix}.${domain}`;
    if (!candidates.has(name)) candidates.set(name, "wordlist");
  }

  const entries = [...candidates.entries()];
  const resolved = await mapPool(entries, 8, async ([name, source]) => {
    const ips = await resolveHost(name);
    if (source === "wordlist" && !ips.length) return null;
    return { subdomain: name, source, ips, queriedAt } satisfies SubdomainResult;
  });

  const results = resolved
    .filter((r): r is SubdomainResult => Boolean(r))
    .sort((a, b) => a.subdomain.localeCompare(b.subdomain));

  const withIps = results.filter((r) => r.ips.length > 0);
  notes.push(
    `Subdomain discovery: ${results.length} candidate(s), ${withIps.length} with DNS A records.`,
  );

  return { results, findings: [], notes };
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
