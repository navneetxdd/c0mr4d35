/**
 * Copies .env.example → .env.local when missing so clones can boot login.
 * Never overwrites an existing .env.local.
 */
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const example = path.join(root, ".env.example");
const local = path.join(root, ".env.local");

if (!fs.existsSync(example)) {
  console.warn("[setup] .env.example missing — cannot bootstrap env");
  process.exit(0);
}

if (fs.existsSync(local)) {
  console.log("[setup] .env.local already exists — leaving it alone");
  process.exit(0);
}

fs.copyFileSync(example, local);
console.log("[setup] Created .env.local from .env.example");
console.log("[setup] Login works with the public Supabase keys.");
console.log("[setup] For Live Scan / assets persistence, add SUPABASE_SERVICE_ROLE_KEY (ask a teammate privately).");
