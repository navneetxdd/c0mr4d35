import type { ScanFinding } from "./risk";

/**
 * Coarse technology fingerprint from response headers + HTML, then correlate
 * the detected ecosystem package with OSV.dev (keyless). We only claim a
 * "stack-family" correlation, never a per-package SBOM, so findings are
 * honestly scoped.
 */

export interface Fingerprint {
  family: string | null;
  ecosystem: "npm" | "PyPI" | "Packagist" | null;
  packageName: string | null;
  version: string | null;
}

export function fingerprint(headers: Record<string, string>, html: string): Fingerprint {
  const powered = (headers["x-powered-by"] ?? "").toLowerCase();
  const server = (headers["server"] ?? "").toLowerCase();
  const generator = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i)?.[1] ?? "";
  const gen = generator.toLowerCase();

  const nextMatch = html.match(/\/_next\/static/) || headers["x-nextjs-cache"];
  if (nextMatch) return { family: "Next.js", ecosystem: "npm", packageName: "next", version: null };

  if (gen.includes("wordpress") || html.includes("/wp-content/")) {
    const v = gen.match(/wordpress\s*([\d.]+)/)?.[1] ?? null;
    return { family: "WordPress", ecosystem: "Packagist", packageName: "wordpress/wordpress", version: v };
  }
  if (powered.includes("express")) return { family: "Express", ecosystem: "npm", packageName: "express", version: null };
  if (gen.includes("drupal") || powered.includes("drupal")) return { family: "Drupal", ecosystem: "Packagist", packageName: "drupal/core", version: null };
  if (server.includes("django") || html.includes("csrfmiddlewaretoken")) return { family: "Django", ecosystem: "PyPI", packageName: "django", version: null };
  if (html.includes("laravel_session") || powered.includes("laravel")) return { family: "Laravel", ecosystem: "Packagist", packageName: "laravel/framework", version: null };

  return { family: null, ecosystem: null, packageName: null, version: null };
}

interface OsvVuln {
  id: string;
  summary?: string;
  severity?: { type: string; score: string }[];
}

export async function correlateOsv(fp: Fingerprint): Promise<ScanFinding[]> {
  if (!fp.ecosystem || !fp.packageName) return [];

  try {
    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        package: { name: fp.packageName, ecosystem: fp.ecosystem },
        ...(fp.version ? { version: fp.version } : {}),
      }),
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as { vulns?: OsvVuln[] };
    const vulns = (data.vulns ?? []).slice(0, 5);
    if (!vulns.length) return [];

    return vulns.map((v) => ({
      id: `cve-${v.id}`,
      category: "CVE" as const,
      risk: "medium" as const,
      title: `${fp.family} stack-family advisory ${v.id}`,
      detail: v.summary ?? `Known advisory affecting the ${fp.family} ecosystem.`,
      remediation: `Confirm the deployed ${fp.family} version and upgrade past ${v.id}.`,
      reference: `https://osv.dev/vulnerability/${v.id}`,
    }));
  } catch {
    return [];
  }
}
