import type { ScanFinding, Risk } from "./risk";
import type { ResolvedTarget } from "./ssrf";
import { fetchWithPin } from "./client";

/**
 * Probes a well-known set of sensitive paths that should never be publicly
 * reachable. Each probe is a bounded GET; we only flag on a high-confidence
 * positive (2xx + a content signature) to avoid false positives from catch-all
 * SPA routes that return 200 for everything. Passive (GET only).
 */

interface PathProbe {
  path: string;
  risk: Risk;
  title: string;
  signature: RegExp;
  remediation: string;
  cwe: string;
  owasp: string;
}

const OWASP_MISCONFIG = "A05:2021 Security Misconfiguration";

const PROBES: PathProbe[] = [
  {
    path: "/.git/HEAD",
    risk: "critical",
    title: "Exposed .git repository",
    signature: /ref:\s*refs\//i,
    remediation: "Block /.git at the edge and rotate any secrets present in history.",
    cwe: "CWE-527",
    owasp: OWASP_MISCONFIG,
  },
  {
    path: "/.git/config",
    risk: "critical",
    title: "Exposed .git config",
    signature: /\[core\]|\[remote/i,
    remediation: "Block /.git at the edge; the repository is downloadable.",
    cwe: "CWE-527",
    owasp: OWASP_MISCONFIG,
  },
  {
    path: "/.env",
    risk: "critical",
    title: "Exposed .env file",
    signature: /^[A-Z0-9_]+=/m,
    remediation: "Remove .env from the web root; rotate all leaked credentials.",
    cwe: "CWE-538",
    owasp: OWASP_MISCONFIG,
  },
  {
    path: "/.env.bak",
    risk: "critical",
    title: "Exposed .env backup file",
    signature: /^[A-Z0-9_]+=/m,
    remediation: "Delete backup env files from the web root; rotate credentials.",
    cwe: "CWE-538",
    owasp: OWASP_MISCONFIG,
  },
  {
    path: "/.aws/credentials",
    risk: "critical",
    title: "Exposed AWS credentials file",
    signature: /aws_access_key_id/i,
    remediation: "Remove the file and rotate the exposed AWS keys immediately.",
    cwe: "CWE-538",
    owasp: OWASP_MISCONFIG,
  },
  {
    path: "/.svn/entries",
    risk: "high",
    title: "Exposed Subversion metadata",
    signature: /^\d+|dir|svn:/im,
    remediation: "Block /.svn at the edge; source metadata is downloadable.",
    cwe: "CWE-527",
    owasp: OWASP_MISCONFIG,
  },
  {
    path: "/.DS_Store",
    risk: "low",
    title: "Exposed .DS_Store file",
    signature: /Bud1|\x00\x00\x00\x01Bud1/,
    remediation: "Remove .DS_Store files; they leak directory structure.",
    cwe: "CWE-527",
    owasp: OWASP_MISCONFIG,
  },
  {
    path: "/phpinfo.php",
    risk: "high",
    title: "Exposed phpinfo()",
    signature: /<title>phpinfo\(\)|PHP Version/i,
    remediation: "Delete phpinfo pages; they disclose full environment and config.",
    cwe: "CWE-200",
    owasp: OWASP_MISCONFIG,
  },
  {
    path: "/server-status",
    risk: "medium",
    title: "Apache server-status exposed",
    signature: /Apache Server Status|Server Version/i,
    remediation: "Restrict mod_status to localhost or disable it.",
    cwe: "CWE-200",
    owasp: OWASP_MISCONFIG,
  },
  {
    path: "/wp-config.php.bak",
    risk: "critical",
    title: "Exposed WordPress config backup",
    signature: /DB_PASSWORD|DB_NAME/i,
    remediation: "Delete config backups from the web root; rotate DB credentials.",
    cwe: "CWE-538",
    owasp: OWASP_MISCONFIG,
  },
  {
    path: "/config.json",
    risk: "medium",
    title: "Publicly readable config.json",
    signature: /["'](secret|api[_-]?key|password|token)["']\s*:/i,
    remediation: "Move configuration server-side; never serve secrets to clients.",
    cwe: "CWE-538",
    owasp: OWASP_MISCONFIG,
  },
  {
    path: "/backup.zip",
    risk: "high",
    title: "Exposed backup archive",
    signature: /^PK\x03\x04/,
    remediation: "Remove backup archives from the web root.",
    cwe: "CWE-538",
    owasp: OWASP_MISCONFIG,
  },
];

export async function probePaths(baseUrl: string, pin: ResolvedTarget): Promise<ScanFinding[]> {
  const origin = new URL(baseUrl).origin;
  const opts = { timeoutMs: 6000, maxBytes: 200_000 } as const;

  const results = await Promise.allSettled(
    PROBES.map(async (probe): Promise<ScanFinding | null> => {
      const res = await fetchWithPin(`${origin}${probe.path}`, pin, opts);
      if (res.status >= 200 && res.status < 300 && probe.signature.test(res.body)) {
        return {
          id: `path-${probe.path.replace(/[^a-z0-9]/gi, "-")}`,
          category: "EXPOSED PATHS",
          risk: probe.risk,
          title: probe.title,
          detail: `${probe.path} returned ${res.status} with a matching content signature.`,
          remediation: probe.remediation,
          evidence: res.body.slice(0, 100).replace(/[^\x20-\x7e]/g, "."),
          owasp: probe.owasp,
          cwe: probe.cwe,
        };
      }
      return null;
    }),
  );

  const out: ScanFinding[] = [];
  for (const r of results) {
    if (r.status === "fulfilled" && r.value) out.push(r.value);
  }

  // Absence-check: responsible-disclosure policy (info-level hygiene).
  try {
    const st = await fetchWithPin(`${origin}/.well-known/security.txt`, pin, { timeoutMs: 5000, maxBytes: 20_000 });
    if (st.status === 404 || st.status === 403) {
      out.push({
        id: "path-securitytxt",
        category: "EXPOSED PATHS",
        risk: "info",
        title: "No security.txt disclosure policy",
        detail: "No responsible-disclosure contact is published at /.well-known/security.txt.",
        remediation: "Publish /.well-known/security.txt with a security contact.",
        owasp: OWASP_MISCONFIG,
        cwe: "CWE-16",
      });
    }
  } catch {
    // ignore
  }

  return out;
}
