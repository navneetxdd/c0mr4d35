/**
 * Production smoke audit — logs NDJSON to debug-749116.log
 * Run: npx playwright test is NOT used; invoke via tsx after playwright install.
 */
import { appendFileSync } from "node:fs";
import { chromium } from "playwright";

const BASE = process.env.AUDIT_BASE_URL ?? "https://systemsiege.vercel.app";
const EMAIL = process.env.AUDIT_EMAIL ?? "";
const PASSWORD = process.env.AUDIT_PASSWORD ?? "";
const LOG = "debug-749116.log";

function log(hypothesisId: string, message: string, data: Record<string, unknown>) {
  appendFileSync(
    LOG,
    JSON.stringify({
      sessionId: "749116",
      runId: "e2e-audit-1",
      hypothesisId,
      location: "scripts/e2e-prod-audit.mts",
      message,
      data,
      timestamp: Date.now(),
    }) + "\n",
  );
}

if (!EMAIL || !PASSWORD) {
  console.error("Set AUDIT_EMAIL and AUDIT_PASSWORD");
  process.exit(1);
}

const pages = [
  { path: "/", name: "dashboard" },
  { path: "/assets", name: "assets" },
  { path: "/scan", name: "scan" },
  { path: "/settings", name: "settings" },
  { path: "/incidents", name: "incidents" },
  { path: "/audit", name: "audit" },
  { path: "/members", name: "members" },
];

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext();
const page = await context.newPage();
const consoleErrors: string[] = [];
page.on("console", (msg) => {
  if (msg.type() === "error") consoleErrors.push(msg.text().slice(0, 200));
});
page.on("pageerror", (err) => consoleErrors.push(err.message.slice(0, 200)));

try {
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded", timeout: 60_000 });
  await page.getByRole("textbox", { name: "Email" }).fill(EMAIL);
  await page.getByRole("textbox", { name: "Password" }).fill(PASSWORD);
  await page.getByRole("button", { name: "Authenticate" }).click();
  await page.waitForURL((url) => !url.pathname.includes("/login"), { timeout: 30_000 });
  log("H-e2e-login", "login ok", { url: page.url() });
  console.log("LOGIN OK", page.url());

  for (const p of pages) {
    consoleErrors.length = 0;
    const res = await page.goto(`${BASE}${p.path}`, { waitUntil: "domcontentloaded", timeout: 60_000 });
    await page.waitForTimeout(1500);
    const status = res?.status() ?? 0;
    const body = await page.locator("body").innerText().catch(() => "");
    const title = await page.title();
    const bouncedToLogin = page.url().includes("/login");
    const hasPlaceholder = /lorem ipsum|TODO|coming soon|placeholder|not implemented/i.test(body);
    const snippet = body.replace(/\s+/g, " ").slice(0, 180);
    const entry = {
      name: p.name,
      path: p.path,
      status,
      title,
      bouncedToLogin,
      hasPlaceholder,
      consoleErrors: [...consoleErrors].slice(0, 5),
      snippet,
    };
    log("H-e2e-page", "page audit", entry);
    console.log(JSON.stringify(entry));
  }

  // Scan: SSRF rejection for loopback IPv4-compatible IPv6
  await page.goto(`${BASE}/scan`, { waitUntil: "domcontentloaded" });
  const target = page.getByLabel(/target/i).or(page.locator('input[name="target"], input[placeholder*="https" i]')).first();
  await target.waitFor({ timeout: 15_000 });
  await target.fill("http://[::127.0.0.1]/");
  await page.getByRole("button", { name: /run assessment/i }).click();
  // Wait for terminal scan state (error or done), not marketing copy.
  await page.waitForFunction(
    () => {
      const t = document.body?.innerText ?? "";
      return /Target resolves to a non-public|Target host could not be resolved|Target host is not permitted|could not be fetched|Assessment failed|posture/i.test(
        t,
      );
    },
    { timeout: 45_000 },
  );
  const after = (await page.locator("body").innerText()).replace(/\s+/g, " ");
  const blocked = /Target resolves to a non-public|Target host is not permitted|non-public address/i.test(after);
  log("H-e2e-ssrf-ui", "scan loopback attempt", {
    blocked,
    body: after.slice(0, 600),
  });
  console.log("SSRF UI blocked=", blocked, after.slice(0, 250));

  // Authenticated API SSRF check
  const api = await page.request.post(`${BASE}/api/scan`, {
    data: { target: "http://[::127.0.0.1]/", stream: false, withAi: false },
    headers: { "content-type": "application/json" },
  });
  const apiBody = await api.text();
  log("H-ssrf-api", "authenticated api scan", {
    status: api.status(),
    body: apiBody.slice(0, 500),
  });
  console.log("API SSRF", api.status(), apiBody.slice(0, 300));

  const cookies = await context.cookies();
  log("H-e2e-session", "cookies present", { count: cookies.length, names: cookies.map((c) => c.name) });
} catch (err) {
  const msg = err instanceof Error ? err.message : String(err);
  log("H-e2e-fail", "audit failed", { error: msg });
  console.error(msg);
  process.exitCode = 1;
} finally {
  await browser.close();
}
