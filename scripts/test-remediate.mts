/**
 * Unit test for the auto-remediation engine. Run: npx tsx scripts/test-remediate.mts
 * No test framework needed — asserts and exits non-zero on failure.
 */
import { buildRemediation, type RemediationInput } from "../src/lib/scan/remediate.ts";

let failures = 0;
function check(name: string, cond: boolean) {
  if (cond) {
    console.log(`  ✓ ${name}`);
  } else {
    console.error(`  ✗ ${name}`);
    failures++;
  }
}

const base: RemediationInput = {
  finalHost: "shop.example.com",
  isHttps: true,
  fingerprint: "nginx",
  techStack: ["nginx", "jQuery 3.5.1"],
  findings: [
    { id: "hdr-content-security-policy", category: "HEADERS", title: "Content-Security-Policy missing" },
    { id: "hdr-strict-transport-security", category: "HEADERS", title: "Strict-Transport-Security missing" },
    { id: "hdr-x-frame-options", category: "HEADERS", title: "X-Frame-Options / frame-ancestors missing" },
  ],
  externalScriptOrigins: [
    "https://cdn.jsdelivr.net/npm/thing.js",
    "https://cdn.jsdelivr.net/npm/other.js", // dupe origin -> collapses
    "https://shop.example.com/self.js", // self origin -> dropped
    "not a url", // unparseable -> ignored
  ],
  formActions: ["https://checkout.stripe.com/pay", "/local-form"],
};

console.log("buildRemediation — populated scan");
const r = buildRemediation(base);
check("returns a remediation object", r !== null);
if (r) {
  check("emits exactly the 3 flagged headers", r.headers.length === 3);
  check("CSP header present", r.headers.some((h) => h.name === "Content-Security-Policy"));
  check("HSTS uses a long max-age", r.headers.some((h) => h.name === "Strict-Transport-Security" && /max-age=63072000/.test(h.value)));
  check("script-src includes the external CDN origin", r.cspEnforce.includes("https://cdn.jsdelivr.net"));
  check("script-src collapses the duplicate CDN origin to one", (r.cspEnforce.match(/cdn\.jsdelivr\.net/g) || []).length === 1);
  check("self-origin script is NOT listed (covered by 'self')", !r.cspEnforce.includes("shop.example.com/self.js") && !r.cspEnforce.includes("https://shop.example.com"));
  check("form-action includes the external Stripe origin", r.cspEnforce.includes("https://checkout.stripe.com"));
  check("frame-ancestors 'none' present (clickjacking)", r.cspEnforce.includes("frame-ancestors 'none'"));
  check("https target adds upgrade-insecure-requests", r.cspEnforce.includes("upgrade-insecure-requests"));
  check("report-only variant carries report-uri", r.cspReportOnly.includes("report-uri /api/csp-report"));
  check("primary platform detected as nginx", r.primary === "nginx");
  check("nginx config is first and uses add_header", r.configs[0]?.platform === "nginx" && r.configs[0].code.includes('add_header Content-Security-Policy'));
  check("a Next.js config variant is also produced", r.configs.some((c) => c.platform === "nextjs" && c.code.includes("async headers()")));
  check("every recommended header appears in the nginx config", r.headers.every((h) => r.configs[0].code.includes(h.name)));
  check("summary is a non-empty human sentence", typeof r.summary === "string" && r.summary.length > 10);
}

console.log("\nbuildRemediation — clean site (no header findings)");
const clean = buildRemediation({ ...base, findings: [{ id: "deface-major", category: "DEFACEMENT", title: "x" }] });
check("returns null when nothing to fix", clean === null);

console.log("\nplatform detection");
check("Next.js fingerprint -> nextjs primary", buildRemediation({ ...base, fingerprint: "Next.js", techStack: ["Next.js"] })?.primary === "nextjs");
check("apache fingerprint -> apache primary", buildRemediation({ ...base, fingerprint: "Apache/2.4", techStack: [] })?.primary === "apache");
check("unknown stack -> nginx default", buildRemediation({ ...base, fingerprint: null, techStack: [] })?.primary === "nginx");

console.log("\ninjection safety");
const quoted = buildRemediation({
  ...base,
  externalScriptOrigins: [],
  findings: [{ id: "hdr-referrer-policy", category: "HEADERS", title: "Referrer-Policy missing" }],
});
check("header values with special chars stay inside quotes (no config break)", quoted !== null && !quoted.configs[0].code.split("\n").some((l) => (l.match(/"/g) || []).length % 2 !== 0));

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
