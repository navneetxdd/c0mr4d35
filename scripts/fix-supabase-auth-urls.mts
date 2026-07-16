/**
 * Patch Supabase Auth Site URL + Redirect allowlist via Management API.
 *
 * Requires a Personal Access Token from:
 * https://supabase.com/dashboard/account/tokens
 *
 * Usage:
 *   $env:SUPABASE_ACCESS_TOKEN='sbp_...'; npx tsx scripts/fix-supabase-auth-urls.mts
 */
import { appendFileSync } from "node:fs";

const REF = process.env.SUPABASE_PROJECT_REF ?? "wvrsbbaydnsyljyqjrhu";
const APP = (process.env.NEXT_PUBLIC_APP_URL ?? "https://systemsiege.vercel.app").replace(/\/$/, "");
const TOKEN = process.env.SUPABASE_ACCESS_TOKEN?.trim();
const LOG = "debug-749116.log";

function log(message: string, data: Record<string, unknown>) {
  appendFileSync(
    LOG,
    JSON.stringify({
      sessionId: "749116",
      runId: "auth-url-fix",
      hypothesisId: "H-site-url",
      location: "scripts/fix-supabase-auth-urls.mts",
      message,
      data,
      timestamp: Date.now(),
    }) + "\n",
  );
}

if (!TOKEN) {
  console.error("Missing SUPABASE_ACCESS_TOKEN (create at supabase.com/dashboard/account/tokens)");
  process.exit(1);
}

const headers = {
  Authorization: `Bearer ${TOKEN}`,
  "Content-Type": "application/json",
};

const getRes = await fetch(`https://api.supabase.com/v1/projects/${REF}/config/auth`, { headers });
const before = (await getRes.json()) as {
  site_url?: string;
  uri_allow_list?: string;
  message?: string;
};
if (!getRes.ok) {
  log("get auth config failed", { status: getRes.status, body: before });
  console.error("GET failed", getRes.status, before);
  process.exit(1);
}

log("auth config before", {
  site_url: before.site_url ?? null,
  uri_allow_list: before.uri_allow_list ?? null,
});
console.log("BEFORE site_url=", before.site_url);
console.log("BEFORE uri_allow_list=", before.uri_allow_list);

const required = [
  `${APP}`,
  `${APP}/`,
  `${APP}/auth/callback`,
  `${APP}/auth/callback/**`,
  "http://localhost:3000",
  "http://localhost:3000/auth/callback",
];
const existing = (before.uri_allow_list ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const merged = Array.from(new Set([...existing, ...required])).join(",");

const patchRes = await fetch(`https://api.supabase.com/v1/projects/${REF}/config/auth`, {
  method: "PATCH",
  headers,
  body: JSON.stringify({
    site_url: APP,
    uri_allow_list: merged,
  }),
});
const after = (await patchRes.json()) as {
  site_url?: string;
  uri_allow_list?: string;
  message?: string;
};
if (!patchRes.ok) {
  log("patch auth config failed", { status: patchRes.status, body: after });
  console.error("PATCH failed", patchRes.status, after);
  process.exit(1);
}

log("auth config after", {
  site_url: after.site_url ?? null,
  uri_allow_list: after.uri_allow_list ?? null,
  ok: after.site_url === APP,
});
console.log("AFTER site_url=", after.site_url);
console.log("AFTER uri_allow_list=", after.uri_allow_list);
console.log(after.site_url === APP ? "OK: site_url updated" : "WARN: site_url mismatch");
