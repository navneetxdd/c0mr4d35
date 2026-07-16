import { resolveTxt, resolveCaa } from "node:dns/promises";
import type { ScanFinding } from "./risk";

/**
 * Passive DNS-based email/domain hardening checks. These query public DNS only
 * (no traffic to the target) for SPF, DMARC, and CAA records — standard posture
 * signals for a security assessment. Runs against the registrable domain.
 */

function registrableDomain(hostname: string): string {
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  // Heuristic for common multi-part public suffixes (co.uk, com.au, etc.).
  const secondLevel = new Set(["co", "com", "org", "net", "gov", "edu", "ac"]);
  const tail = parts.slice(-2);
  if (secondLevel.has(tail[0]!) && tail[1]!.length === 2) {
    return parts.slice(-3).join(".");
  }
  return tail.join(".");
}

function withTimeout<T>(p: Promise<T>, ms: number, fallback: T): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((resolve) => setTimeout(() => resolve(fallback), ms)),
  ]).catch(() => fallback);
}

async function txt(name: string): Promise<string[]> {
  try {
    const records = await withTimeout(resolveTxt(name), 5000, [] as string[][]);
    return records.map((chunks) => chunks.join(""));
  } catch {
    return [];
  }
}

export async function checkDns(hostname: string): Promise<ScanFinding[]> {
  const domain = registrableDomain(hostname);
  const out: ScanFinding[] = [];

  const [rootTxt, dmarcTxt, caa] = await Promise.all([
    txt(domain),
    txt(`_dmarc.${domain}`),
    withTimeout(resolveCaa(domain), 5000, [] as unknown[]).catch(() => [] as unknown[]),
  ]);

  const hasSpf = rootTxt.some((r) => /v=spf1/i.test(r));
  const hasDmarc = dmarcTxt.some((r) => /v=DMARC1/i.test(r));

  if (!hasSpf) {
    out.push({
      id: "dns-spf",
      category: "DNS",
      risk: "low",
      title: "No SPF record",
      detail: `${domain} publishes no SPF (v=spf1) TXT record, so receivers cannot verify which servers may send mail for the domain (spoofing risk).`,
      remediation: "Publish an SPF record listing authorized senders, e.g. \"v=spf1 include:_spf.provider.com -all\".",
      owasp: "A05:2021 Security Misconfiguration",
      cwe: "CWE-16",
    });
  }
  if (!hasDmarc) {
    out.push({
      id: "dns-dmarc",
      category: "DNS",
      risk: "low",
      title: "No DMARC policy",
      detail: `${domain} publishes no DMARC record, leaving email authentication unenforced and enabling brand spoofing/phishing.`,
      remediation: "Publish a DMARC record at _dmarc." + domain + ", starting with p=none for monitoring then tightening to quarantine/reject.",
      owasp: "A05:2021 Security Misconfiguration",
      cwe: "CWE-16",
    });
  }
  if (Array.isArray(caa) && caa.length === 0) {
    out.push({
      id: "dns-caa",
      category: "DNS",
      risk: "info",
      title: "No CAA record",
      detail: `${domain} has no CAA record, so any CA may issue certificates for it.`,
      remediation: "Publish a CAA record naming your authorized certificate authority.",
      owasp: "A05:2021 Security Misconfiguration",
      cwe: "CWE-295",
    });
  }

  return out;
}
