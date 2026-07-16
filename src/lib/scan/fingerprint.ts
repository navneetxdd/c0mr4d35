import type { ScanFinding, Risk } from "./risk";

/**
 * Technology fingerprint from response headers + HTML, with version extraction
 * where possible, then correlate versioned components against OSV.dev (keyless).
 *
 * Honesty contract: we ONLY emit a CVE finding when we have an actual version
 * to query. If a technology is detected without a confirmable version, we emit
 * an info-level "technology detected" note — never a fabricated advisory. This
 * avoids the "unversioned keyword → generic CVE" false-positive trap.
 */

export interface Component {
  family: string;
  ecosystem: "npm" | "PyPI" | "Packagist";
  packageName: string;
  version: string | null;
}

export interface Fingerprint {
  family: string | null;
  components: Component[];
}

function metaGenerator(html: string): string {
  return (html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i)?.[1] ?? "").toLowerCase();
}

export function fingerprint(headers: Record<string, string>, html: string): Fingerprint {
  const powered = (headers["x-powered-by"] ?? "").toLowerCase();
  const server = (headers["server"] ?? "").toLowerCase();
  const gen = metaGenerator(html);
  const components: Component[] = [];
  let family: string | null = null;

  // Server-side frameworks / CMS.
  if (html.includes("/wp-content/") || gen.includes("wordpress")) {
    family = "WordPress";
    components.push({
      family: "WordPress",
      ecosystem: "Packagist",
      packageName: "wordpress/wordpress",
      version: gen.match(/wordpress\s*([\d.]+)/)?.[1] ?? null,
    });
  } else if (html.match(/\/_next\/static/) || headers["x-nextjs-cache"]) {
    family = "Next.js";
    components.push({ family: "Next.js", ecosystem: "npm", packageName: "next", version: null });
  } else if (powered.includes("express")) {
    family = "Express";
    components.push({ family: "Express", ecosystem: "npm", packageName: "express", version: null });
  } else if (gen.includes("drupal") || powered.includes("drupal")) {
    family = "Drupal";
    components.push({ family: "Drupal", ecosystem: "Packagist", packageName: "drupal/core", version: gen.match(/drupal\s*([\d.]+)/)?.[1] ?? null });
  } else if (server.includes("django") || html.includes("csrfmiddlewaretoken")) {
    family = "Django";
    components.push({ family: "Django", ecosystem: "PyPI", packageName: "django", version: null });
  } else if (html.includes("laravel_session") || powered.includes("laravel")) {
    family = "Laravel";
    components.push({ family: "Laravel", ecosystem: "Packagist", packageName: "laravel/framework", version: null });
  }

  // Client-side libraries with versions in the asset path — these give us a
  // real version to query, so they yield high-confidence CVE correlation.
  const jq = html.match(/jquery[.-]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i)?.[1];
  if (jq) components.push({ family: `jQuery ${jq}`, ecosystem: "npm", packageName: "jquery", version: jq });

  const bs = html.match(/bootstrap[.-]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)/i)?.[1];
  if (bs) components.push({ family: `Bootstrap ${bs}`, ecosystem: "npm", packageName: "bootstrap", version: bs });

  const ng = html.match(/angular[.-]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i)?.[1];
  if (ng) components.push({ family: `AngularJS ${ng}`, ecosystem: "npm", packageName: "angular", version: ng });

  if (!family && components.length) family = components[0]!.family;
  return { family, components };
}

interface OsvVuln {
  id: string;
  summary?: string;
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string };
}

function osvRisk(v: OsvVuln): Risk {
  const sev = (v.database_specific?.severity ?? v.severity?.[0]?.score ?? "").toUpperCase();
  if (sev.includes("CRITICAL") || /(^|[^\d])9(\.\d)?/.test(sev)) return "high";
  if (sev.includes("HIGH")) return "high";
  if (sev.includes("MODERATE") || sev.includes("MEDIUM")) return "medium";
  if (sev.includes("LOW")) return "low";
  return "medium";
}

async function queryOsv(c: Component): Promise<ScanFinding[]> {
  try {
    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        package: { name: c.packageName, ecosystem: c.ecosystem },
        version: c.version,
      }),
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as { vulns?: OsvVuln[] };
    const vulns = (data.vulns ?? []).slice(0, 5);
    return vulns.map((v) => ({
      id: `cve-${v.id}`,
      category: "CVE" as const,
      risk: osvRisk(v),
      title: `${c.family}: known vulnerability ${v.id}`,
      detail: v.summary ?? `Advisory ${v.id} affects ${c.packageName}@${c.version}.`,
      remediation: `Upgrade ${c.packageName} past the version affected by ${v.id}.`,
      reference: `https://osv.dev/vulnerability/${v.id}`,
      evidence: `${c.packageName}@${c.version}`,
      owasp: "A06:2021 Vulnerable and Outdated Components",
      cwe: "CWE-1035",
    }));
  } catch {
    return [];
  }
}

export async function correlateOsv(fp: Fingerprint): Promise<ScanFinding[]> {
  const out: ScanFinding[] = [];
  const versioned = fp.components.filter((c) => c.version);
  const unversioned = fp.components.filter((c) => !c.version);

  // Query OSV only for components we have a real version for.
  const results = await Promise.allSettled(versioned.map(queryOsv));
  for (const r of results) {
    if (r.status === "fulfilled") out.push(...r.value);
  }

  // Detected-but-unconfirmed tech: honest info note, not a fabricated CVE.
  for (const c of unversioned) {
    out.push({
      id: `tech-${c.packageName}`,
      category: "CVE",
      risk: "info",
      title: `${c.family} detected (version unconfirmed)`,
      detail: `The stack appears to use ${c.family}, but no exact version was disclosed, so specific advisories cannot be confirmed.`,
      remediation: `Confirm the deployed ${c.family} version and check it against OSV/NVD advisories.`,
      owasp: "A06:2021 Vulnerable and Outdated Components",
      cwe: "CWE-1035",
    });
  }

  return out;
}
