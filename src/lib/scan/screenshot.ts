import "server-only";

import type { Browser, Page, Response } from "playwright-core";
import { isIP } from "node:net";
import { isPublicAddress, resolveTarget, SsrfError, type ResolvedTarget } from "./ssrf";

const VIEWPORT = { width: 1440, height: 900 };
const CHROMIUM_PACK_TIMEOUT_MS = 90_000;

/** Must match @sparticuz/chromium-min major.minor.patch (Vercel x64). */
const DEFAULT_CHROMIUM_PACK =
  "https://github.com/Sparticuz/chromium/releases/download/v149.0.0/chromium-v149.0.0-pack.x64.tar";

export interface ScreenshotCaptureResult {
  ok: boolean;
  png?: Buffer;
  error?: string;
}

function isServerlessRuntime(): boolean {
  return Boolean(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);
}

async function resolveSparticuzArgs(
  chromiumMod: typeof import("@sparticuz/chromium-min").default,
): Promise<string[]> {
  const raw = chromiumMod.args as string[] | (() => Promise<string[]>) | (() => string[]);
  if (typeof raw === "function") {
    return await Promise.resolve(raw());
  }
  return Array.isArray(raw) ? raw : [];
}

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms),
    ),
  ]);
}

/**
 * Launch a dedicated Chromium with hostname pinned to the SSRF-validated IP.
 * This closes the DNS-rebinding TOCTOU window between resolveTarget and navigation.
 */
async function launchPinnedBrowser(pinned: ResolvedTarget): Promise<Browser> {
  const { chromium } = await import("playwright-core");
  const host = pinned.hostname;
  const ip = isIP(pinned.address) === 6 ? `[${pinned.address}]` : pinned.address;
  // MAP hostname to the exact IP we already validated as public.
  const resolverRules = `MAP ${host} ${ip}, EXCLUDE localhost`;

  if (isServerlessRuntime()) {
    const sparticuzMod = await import("@sparticuz/chromium-min");
    const sparticuz = sparticuzMod.default;
    const packUrl = process.env.CHROMIUM_REMOTE_EXEC_PATH?.trim() || DEFAULT_CHROMIUM_PACK;
    const executablePath = await withTimeout(
      sparticuz.executablePath(packUrl),
      CHROMIUM_PACK_TIMEOUT_MS,
      "Chromium pack download",
    );
    const args = await resolveSparticuzArgs(sparticuz);
    return chromium.launch({
      args: [
        ...args,
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        `--host-resolver-rules=${resolverRules}`,
      ],
      executablePath,
      headless: true,
    });
  }

  const override = process.env.CHROMIUM_EXECUTABLE_PATH;
  const pinArgs = [`--host-resolver-rules=${resolverRules}`];
  if (override) {
    return chromium.launch({ executablePath: override, headless: true, args: pinArgs });
  }
  try {
    return await chromium.launch({ channel: "chrome", headless: true, args: pinArgs });
  } catch {
    try {
      return await chromium.launch({ channel: "msedge", headless: true, args: pinArgs });
    } catch {
      return chromium.launch({ headless: true, args: pinArgs });
    }
  }
}

function isHttpUrl(raw: string): boolean {
  try {
    const u = new URL(raw);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

async function assertPublicRemote(response: Response | null): Promise<void> {
  if (!response) return;
  try {
    const addr = await response.serverAddr();
    if (addr?.ipAddress && !isPublicAddress(addr.ipAddress)) {
      throw new SsrfError("Screenshot blocked: connection landed on a non-public address");
    }
  } catch (error) {
    if (error instanceof SsrfError) throw error;
  }
}

async function installSsrfRouteGuard(page: Page, pinnedHost: string): Promise<void> {
  await page.route("**/*", async (route) => {
    const req = route.request();
    const next = req.url();
    if (!isHttpUrl(next)) {
      await route.continue();
      return;
    }

    let host: string;
    try {
      host = new URL(next).hostname.toLowerCase();
    } catch {
      await route.abort("blockedbyclient");
      return;
    }

    if (isIP(host) && !isPublicAddress(host)) {
      await route.abort("blockedbyclient");
      return;
    }

    // Main-frame navigations (incl. redirects) must clear resolveTarget again.
    if (req.isNavigationRequest() && req.frame() === page.mainFrame()) {
      try {
        // Same host stays pinned by Chromium resolver rules; still validate scheme/port/public.
        await resolveTarget(next);
        await route.continue();
      } catch {
        await route.abort("blockedbyclient");
      }
      return;
    }

    // Cross-host navigations inside subframes / top-level redirects already handled above.
    // Subresources to other hosts: block private IP literals only (checked above).
    void pinnedHost;
    await route.continue();
  });
}

export async function captureScreenshot(url: string): Promise<ScreenshotCaptureResult> {
  let browser: Browser | null = null;
  try {
    const pinned = await resolveTarget(url);
    browser = await launchPinnedBrowser(pinned);

    const context = await browser.newContext({
      viewport: VIEWPORT,
      deviceScaleFactor: 1,
      userAgent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    });
    const page = await context.newPage();
    page.on("dialog", (dialog) => dialog.dismiss().catch(() => undefined));
    await installSsrfRouteGuard(page, pinned.hostname);

    try {
      const response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 25_000 });
      if (!response) {
        return { ok: false, error: "Screenshot navigation produced no response" };
      }

      await assertPublicRemote(response);

      const landed = page.url();
      if (isHttpUrl(landed)) {
        await resolveTarget(landed);
      }

      // Defense in depth: DNS must still only yield public addresses.
      const again = await resolveTarget(url);
      if (!isPublicAddress(again.address)) {
        return { ok: false, error: "Screenshot blocked: DNS rebinding to a non-public address" };
      }

      await page.waitForLoadState("networkidle", { timeout: 4_000 }).catch(() => undefined);
      await page
        .addStyleTag({
          content:
            "*,:before,:after{animation:none!important;transition:none!important;caret-color:transparent!important}",
        })
        .catch(() => undefined);
      const png = await page.screenshot({ type: "png", animations: "disabled" });
      return { ok: true, png };
    } finally {
      await context.close().catch(() => undefined);
    }
  } catch (error) {
    const message =
      error instanceof SsrfError
        ? error.message
        : error instanceof Error
          ? error.message
          : "Screenshot capture failed";
    return { ok: false, error: message };
  } finally {
    if (browser) {
      await browser.close().catch(() => undefined);
    }
  }
}
