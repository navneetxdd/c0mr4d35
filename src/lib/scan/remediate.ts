import type { ScanFinding } from "./risk";

/**
 * Auto-remediation engine ("self-writing firewall").
 *
 * Turns findings + the observed resource inventory into a copy-paste fix: a
 * generated Content-Security-Policy and the exact header config for the target's
 * detected server stack. Everything here is DERIVED from the scan — no values
 * are hardcoded to any specific site. It is a pure function of scan data, so it
 * is recomputed wherever a scan is displayed (no persistence, no DB surface).
 */

export type RemediationPlatform = "nginx" | "apache" | "caddy" | "nextjs" | "cloudflare-worker";

export interface RecommendedHeader {
  name: string;
  value: string;
  reason: string;
}

export interface RemediationConfig {
  platform: RemediationPlatform;
  label: string;
  language: string;
  code: string;
}

export interface Remediation {
  /** Safe rollout policy (violations reported, nothing blocked). */
  cspReportOnly: string;
  /** Enforcing policy for once report-only is clean. */
  cspEnforce: string;
  headers: RecommendedHeader[];
  configs: RemediationConfig[];
  primary: RemediationPlatform;
  summary: string;
  notes: string[];
}

export interface RemediationInput {
  finalHost: string;
  isHttps: boolean;
  fingerprint: string | null;
  techStack: string[];
  findings: Pick<ScanFinding, "id" | "category" | "title">[];
  externalScriptOrigins: string[];
  formActions: string[];
}

/** Reduce a URL to its origin token (scheme://host[:port]); null if unparseable. */
function toOrigin(raw: string): string | null {
  try {
    const u = new URL(raw);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.origin;
  } catch {
    return null;
  }
}

/** Distinct external origins (self-origin dropped — it's covered by 'self'). */
function externalOrigins(urls: string[], selfHost: string, selfHttps: boolean): string[] {
  const self = `${selfHttps ? "https" : "http"}://${selfHost}`;
  const set = new Set<string>();
  for (const raw of urls) {
    const origin = toOrigin(raw);
    if (!origin || origin === self) continue;
    set.add(origin);
  }
  return [...set].sort();
}

function buildCsp(input: RemediationInput): { reportOnly: string; enforce: string } {
  const scriptExternal = externalOrigins(input.externalScriptOrigins, input.finalHost, input.isHttps);
  const formExternal = externalOrigins(input.formActions, input.finalHost, input.isHttps);

  const directives: string[] = [
    "default-src 'self'",
    `script-src 'self'${scriptExternal.length ? " " + scriptExternal.join(" ") : ""}`,
    // Pragmatic starters — tune from report-uri violations before enforcing.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    `form-action 'self'${formExternal.length ? " " + formExternal.join(" ") : ""}`,
  ];
  if (input.isHttps) directives.push("upgrade-insecure-requests");

  const base = directives.join("; ");
  return {
    enforce: base,
    reportOnly: `${base}; report-uri /api/csp-report`,
  };
}

interface HeaderRecipe {
  findingId: string;
  name: string;
  value: string;
  reason: string;
}

function recommendedHeaders(input: RemediationInput, cspEnforce: string): RecommendedHeader[] {
  const ids = new Set(input.findings.map((f) => f.id));
  // A finding is "present" if its exact id or its weak-variant id was raised.
  const flagged = (base: string) => ids.has(base) || ids.has(`${base}-weak`);

  const recipes: HeaderRecipe[] = [
    {
      findingId: "hdr-content-security-policy",
      name: "Content-Security-Policy",
      value: cspEnforce,
      reason: "No enforced CSP — this policy is generated from the scripts and forms observed on the page.",
    },
    {
      findingId: "hdr-strict-transport-security",
      name: "Strict-Transport-Security",
      value: "max-age=63072000; includeSubDomains; preload",
      reason: "Forces HTTPS for two years and eligibility for the preload list.",
    },
    {
      findingId: "hdr-x-frame-options",
      name: "X-Frame-Options",
      value: "DENY",
      reason: "Blocks the page from being framed (clickjacking).",
    },
    {
      findingId: "hdr-x-content-type-options",
      name: "X-Content-Type-Options",
      value: "nosniff",
      reason: "Stops MIME-type sniffing.",
    },
    {
      findingId: "hdr-referrer-policy",
      name: "Referrer-Policy",
      value: "strict-origin-when-cross-origin",
      reason: "Trims referrer leakage to cross-origin destinations.",
    },
    {
      findingId: "hdr-permissions-policy",
      name: "Permissions-Policy",
      value: "camera=(), microphone=(), geolocation=(), interest-cohort=()",
      reason: "Denies powerful browser features by default.",
    },
  ];

  return recipes.filter((r) => flagged(r.findingId)).map(({ name, value, reason }) => ({ name, value, reason }));
}

function detectPlatform(input: RemediationInput): RemediationPlatform {
  const hay = `${input.fingerprint ?? ""} ${input.techStack.join(" ")}`.toLowerCase();
  if (/next\.?js/.test(hay)) return "nextjs";
  if (/nginx/.test(hay)) return "nginx";
  if (/apache|httpd/.test(hay)) return "apache";
  if (/caddy/.test(hay)) return "caddy";
  if (/cloudflare/.test(hay)) return "cloudflare-worker";
  return "nginx"; // most portable default
}

function esc(value: string, quote: '"' | "'"): string {
  return value.split(quote).join(quote === '"' ? '\\"' : "\\'");
}

function renderConfig(platform: RemediationPlatform, headers: RecommendedHeader[]): RemediationConfig {
  const meta: Record<RemediationPlatform, { label: string; language: string }> = {
    nginx: { label: "nginx", language: "nginx" },
    apache: { label: "Apache (.htaccess)", language: "apache" },
    caddy: { label: "Caddy", language: "caddy" },
    nextjs: { label: "Next.js (next.config)", language: "typescript" },
    "cloudflare-worker": { label: "Cloudflare Worker", language: "javascript" },
  };

  let code: string;
  switch (platform) {
    case "nginx":
      code = headers.map((h) => `add_header ${h.name} "${esc(h.value, '"')}" always;`).join("\n");
      break;
    case "apache":
      code = headers.map((h) => `Header always set ${h.name} "${esc(h.value, '"')}"`).join("\n");
      break;
    case "caddy":
      code = `header {\n${headers.map((h) => `  ${h.name} "${esc(h.value, '"')}"`).join("\n")}\n}`;
      break;
    case "nextjs":
      code =
        `// next.config.ts — add to the config object\n` +
        `async headers() {\n  return [\n    {\n      source: "/:path*",\n      headers: [\n` +
        headers.map((h) => `        { key: "${h.name}", value: "${esc(h.value, '"')}" },`).join("\n") +
        `\n      ],\n    },\n  ];\n}`;
      break;
    case "cloudflare-worker":
      code =
        `// Wrap your fetch handler's Response\n` +
        headers.map((h) => `response.headers.set("${h.name}", "${esc(h.value, '"')}");`).join("\n");
      break;
  }

  return { platform, label: meta[platform].label, language: meta[platform].language, code };
}

const PLATFORM_ORDER: RemediationPlatform[] = ["nginx", "nextjs", "apache", "caddy", "cloudflare-worker"];

/**
 * Build the full remediation package for a scan. Returns null when there is
 * nothing to fix (no header/CSP findings), so callers can hide the panel.
 */
export function buildRemediation(input: RemediationInput): Remediation | null {
  const { reportOnly, enforce } = buildCsp(input);
  const headers = recommendedHeaders(input, enforce);
  if (headers.length === 0) return null;

  const primary = detectPlatform(input);
  const ordered = [primary, ...PLATFORM_ORDER.filter((p) => p !== primary)];
  const configs = ordered.map((p) => renderConfig(p, headers));

  const notes = [
    "Roll out the CSP in Report-Only first, watch /api/csp-report for violations, then switch to enforcing.",
    "connect-src, img-src and style-src are conservative starters — widen them only for origins your app legitimately uses.",
  ];
  if (headers.some((h) => h.name === "Content-Security-Policy")) {
    notes.push("The CSP allowlist was built from the external script and form origins actually observed on this page.");
  }

  const cspInHeaders = headers.some((h) => h.name === "Content-Security-Policy");
  const summary =
    `${headers.length} hardening header${headers.length === 1 ? "" : "s"}` +
    (cspInHeaders ? " (including a generated CSP)" : "") +
    ` ready for ${configs[0]?.label ?? primary}.`;

  return { cspReportOnly: reportOnly, cspEnforce: enforce, headers, configs, primary, summary, notes };
}
