import { appendFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { isPublicAddress, resolveTarget } from "../src/lib/scan/ssrf.ts";
import { discoverSubdomains } from "../src/lib/scan/subdomains.ts";

function log(hypothesisId: string, message: string, data: Record<string, unknown>) {
  appendFileSync(
    "debug-749116.log",
    JSON.stringify({
      sessionId: "749116",
      runId: "post-fix",
      hypothesisId,
      location: "scripts/post-fix-security.mts",
      message,
      data,
      timestamp: Date.now(),
    }) + "\n",
  );
}

let hits = "";
try {
  hits = execSync('rg -n "127\\.0\\.0\\.1:7781" src', { encoding: "utf8" });
} catch {
  hits = "";
}
log("H-telemetry", "7781 grep", { hits: hits.trim() || "NONE" });
console.log("telemetry", hits.trim() || "NONE");

const blocked = ["::127.0.0.1", "::7f00:1", "::ffff:127.0.0.1", "::ffff:7f00:1"].map((a) => ({
  a,
  pub: isPublicAddress(a),
}));
log("H-ssrf-ipv6", "post-fix public checks", { blocked });
console.log("ssrf", blocked);

for (const raw of ["http://[::127.0.0.1]/", "http://[::7f00:1]/"]) {
  try {
    await resolveTarget(raw);
    log("H-ssrf-resolve", "UNEXPECTED allow", { raw });
  } catch (e) {
    log("H-ssrf-resolve", "blocked", { raw, error: e instanceof Error ? e.message : String(e) });
  }
}

const sub = await discoverSubdomains("1.1.1.1");
log("H-subdomain-ip", "post-fix IP skip", { notes: sub.notes, n: sub.results.length });
console.log("sub", sub.notes);

const res = await fetch("https://systemsiege.vercel.app/api/scan", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ target: "http://[::127.0.0.1]/" }),
});
const text = await res.text();
log("H-ssrf-api", "api scan loopback", { status: res.status, body: text.slice(0, 400) });
console.log("api", res.status, text.slice(0, 300));

const audit = await fetch("https://systemsiege.vercel.app/audit", { redirect: "manual" });
log("H-audit", "audit HTTP", { status: audit.status, location: audit.headers.get("location") });
console.log("audit", audit.status);
