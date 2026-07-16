/**
 * Ensure .env.local has the public Supabase keys needed to boot /login.
 * - Creates .env.local from .env.example when missing
 * - Merges missing/blank NEXT_PUBLIC_* keys when .env.local already exists
 * - Never overwrites non-empty private keys (service role, BYOK, cron, etc.)
 */
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const examplePath = path.join(root, ".env.example");
const localPath = path.join(root, ".env.local");

const REQUIRED_PUBLIC = [
  "NEXT_PUBLIC_SUPABASE_URL",
  "NEXT_PUBLIC_SUPABASE_ANON_KEY",
  "NEXT_PUBLIC_APP_URL",
];

function stripBom(text) {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

function parseEnv(text) {
  /** @type {Map<string, string>} */
  const map = new Map();
  /** @type {string[]} */
  const order = [];
  for (const raw of stripBom(text).split(/\r?\n/)) {
    const line = raw;
    const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!m) continue;
    const key = m[1];
    const value = m[2] ?? "";
    if (!map.has(key)) order.push(key);
    map.set(key, value);
  }
  return { map, order };
}

function serializeEnv(map, order, headerLines) {
  const lines = [...headerLines];
  const seen = new Set();
  for (const key of order) {
    if (!map.has(key) || seen.has(key)) continue;
    seen.add(key);
    lines.push(`${key}=${map.get(key)}`);
  }
  for (const [key, value] of map) {
    if (seen.has(key)) continue;
    lines.push(`${key}=${value}`);
  }
  return `${lines.join("\n").replace(/\n+$/, "")}\n`;
}

if (!fs.existsSync(examplePath)) {
  console.warn("[setup] .env.example missing — cannot bootstrap env");
  process.exit(0);
}

const exampleRaw = stripBom(fs.readFileSync(examplePath, "utf8"));
// Rewrite example without BOM so Next.js always parses keys.
fs.writeFileSync(examplePath, exampleRaw.endsWith("\n") ? exampleRaw : `${exampleRaw}\n`, "utf8");

const example = parseEnv(exampleRaw);
const header = [
  "# Datum — local environment (auto-managed by npm run setup)",
  "# Public NEXT_PUBLIC_* keys are filled from .env.example.",
  "# Private keys (SERVICE_ROLE / BYOK / CRON) stay blank unless you set them.",
  "",
];

if (!fs.existsSync(localPath)) {
  fs.writeFileSync(localPath, exampleRaw.endsWith("\n") ? exampleRaw : `${exampleRaw}\n`, "utf8");
  console.log("[setup] Created .env.local from .env.example");
} else {
  const localRaw = fs.readFileSync(localPath, "utf8");
  const local = parseEnv(localRaw);
  let changed = false;

  for (const key of REQUIRED_PUBLIC) {
    const fromExample = (example.map.get(key) ?? "").trim();
    const current = (local.map.get(key) ?? "").trim();
    if (!current && fromExample) {
      local.map.set(key, fromExample);
      if (!local.order.includes(key)) local.order.push(key);
      changed = true;
      console.log(`[setup] Filled missing ${key}`);
    }
  }

  // Also fill other blank keys from example only when example has a non-empty value
  // (never invent secrets; example keeps service role empty).
  for (const [key, value] of example.map) {
    if (REQUIRED_PUBLIC.includes(key)) continue;
    const exampleVal = value.trim();
    if (!exampleVal) continue;
    const current = (local.map.get(key) ?? "").trim();
    if (!current) {
      local.map.set(key, value);
      if (!local.order.includes(key)) local.order.push(key);
      changed = true;
      console.log(`[setup] Filled missing ${key}`);
    }
  }

  if (changed || localRaw.charCodeAt(0) === 0xfeff) {
    const order = [...new Set([...REQUIRED_PUBLIC, ...local.order, ...example.order])];
    fs.writeFileSync(localPath, serializeEnv(local.map, order, header), "utf8");
    console.log("[setup] Updated .env.local");
  } else {
    console.log("[setup] .env.local already has required public keys");
  }
}

const finalLocal = parseEnv(fs.readFileSync(localPath, "utf8"));
const missing = REQUIRED_PUBLIC.filter((k) => !(finalLocal.map.get(k) ?? "").trim());
if (missing.length) {
  console.error(`[setup] Still missing: ${missing.join(", ")}. Check .env.example then re-run npm run setup.`);
  process.exit(1);
}

console.log("[setup] Public Supabase env ready — restart `npm run dev` if it was already running.");
console.log("[setup] For Live Scan, add SUPABASE_SERVICE_ROLE_KEY privately (or use https://systemsiege.vercel.app).");
