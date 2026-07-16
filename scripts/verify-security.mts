import { appendFileSync } from "node:fs";
import { isIP } from "node:net";
import { isPublicAddress, resolveTarget } from "../src/lib/scan/ssrf.ts";
import { discoverSubdomains } from "../src/lib/scan/subdomains.ts";

const logPath = new URL("../debug-749116.log", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");

function log(hypothesisId, message, data) {
  appendFileSync(
    logPath,
    JSON.stringify({
      sessionId: "749116",
      runId: "security-verify-1",
      hypothesisId,
      location: "scripts/verify-security.mts",
      message,
      data,
      timestamp: Date.now(),
    }) + "\n",
  );
}

const cases = [
  "::127.0.0.1",
  "::ffff:127.0.0.1",
  "::ffff:7f00:1",
  "::7f00:1",
  "::1",
  "127.0.0.1",
  "169.254.169.254",
  "8.8.8.8",
  "2001:4860:4860::8888",
];

for (const addr of cases) {
  const kind = isIP(addr);
  const pub = isPublicAddress(addr);
  log("H-ssrf-ipv6", "isPublicAddress", { addr, kind, pub });
  console.log(addr, "isIP=" + kind, "public=" + pub);
}

const urlCases = [
  "http://[::127.0.0.1]/",
  "http://[::ffff:127.0.0.1]/",
  "http://[::7f00:1]/",
  "http://127.0.0.1/",
];

for (const raw of urlCases) {
  try {
    const r = await resolveTarget(raw);
    log("H-ssrf-resolve", "resolveTarget ok (UNEXPECTED)", { raw, address: r.address });
    console.log("resolve OK UNEXPECTED", raw, "->", r.address);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    log("H-ssrf-resolve", "resolveTarget blocked", { raw, error: msg });
    console.log("resolve BLOCK", raw, msg);
  }
}

const sub = await discoverSubdomains("1.1.1.1");
log("H-subdomain-ip", "discoverSubdomains IP", {
  results: sub.results.length,
  notes: sub.notes,
});
console.log("subdomains 1.1.1.1", sub.notes, "results", sub.results.length);

const originConfigured = (process.env.NEXT_PUBLIC_APP_URL || "").replace(/\/$/, "") || null;
log("H-auth-origin", "NEXT_PUBLIC_APP_URL", { originConfigured });
console.log("APP_URL", originConfigured);
