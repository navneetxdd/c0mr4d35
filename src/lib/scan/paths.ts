import type { ScanFinding, Risk } from "./risk";
import type { ResolvedTarget } from "./ssrf";
import { guardedFetch } from "./fetch";

/**
 * Probes a small, well-known set of sensitive paths that should never be
 * publicly reachable. Each probe is a bounded GET; we only flag on a
 * high-confidence positive (2xx + a content signature) to avoid false
 * positives from catch-all SPA routes that return 200 for everything.
 */

interface PathProbe {
  path: string;
  risk: Risk;
  title: string;
  signature: RegExp;
  remediation: string;
}

const PROBES: PathProbe[] = [
  {
    path: "/.git/HEAD",
    risk: "critical",
    title: "Exposed .git repository",
    signature: /ref:\s*refs\//i,
    remediation: "Block /.git at the edge and rotate any secrets present in history.",
  },
  {
    path: "/.env",
    risk: "critical",
    title: "Exposed .env file",
    signature: /^[A-Z0-9_]+=/m,
    remediation: "Remove .env from the web root; rotate all leaked credentials.",
  },
  {
    path: "/.aws/credentials",
    risk: "critical",
    title: "Exposed AWS credentials file",
    signature: /aws_access_key_id/i,
    remediation: "Remove the file and rotate the exposed AWS keys immediately.",
  },
  {
    path: "/config.json",
    risk: "medium",
    title: "Publicly readable config.json",
    signature: /["'](secret|api[_-]?key|password|token)["']\s*:/i,
    remediation: "Move configuration server-side; never serve secrets to clients.",
  },
  {
    path: "/.well-known/security.txt",
    risk: "info",
    title: "No security.txt disclosure policy",
    signature: /^$/,
    remediation: "Publish /.well-known/security.txt with a contact for responsible disclosure.",
  },
];

export async function probePaths(baseUrl: string, pin: ResolvedTarget): Promise<ScanFinding[]> {
  const origin = new URL(baseUrl).origin;
  const fetchOpts = { pin, timeoutMs: 6000 } as const;
  const results = await Promise.allSettled(
    PROBES.map(async (probe): Promise<ScanFinding | null> => {
      // security.txt is an absence-check; handle separately.
      if (probe.path === "/.well-known/security.txt") {
        const res = await guardedFetch(`${origin}${probe.path}`, { ...fetchOpts, maxBytes: 20_000 });
        return res.status === 404 || res.status === 403
          ? ({
              id: "path-securitytxt",
              category: "EXPOSED PATHS" as const,
              risk: probe.risk,
              title: probe.title,
              detail: "No responsible-disclosure contact is published.",
              remediation: probe.remediation,
            } satisfies ScanFinding)
          : null;
      }

      const res = await guardedFetch(`${origin}${probe.path}`, { ...fetchOpts, maxBytes: 200_000 });
      if (res.status >= 200 && res.status < 300 && probe.signature.test(res.body)) {
        return {
          id: `path-${probe.path.replace(/[^a-z0-9]/gi, "-")}`,
          category: "EXPOSED PATHS" as const,
          risk: probe.risk,
          title: probe.title,
          detail: `${probe.path} returned ${res.status} with matching content signature.`,
          remediation: probe.remediation,
          evidence: res.body.slice(0, 120),
        } satisfies ScanFinding;
      }
      return null;
    }),
  );

  const out: ScanFinding[] = [];
  for (const r of results) {
    if (r.status === "fulfilled" && r.value) out.push(r.value);
  }
  return out;
}
