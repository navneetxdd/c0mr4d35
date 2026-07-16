import "server-only";

import type { Browser } from "playwright-core";
import { resolveTarget, SsrfError } from "./ssrf";

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

let browserPromise: Promise<Browser> | null = null;

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

async function getBrowser(): Promise<Browser> {
  if (browserPromise) return browserPromise;

  browserPromise = (async () => {
    const { chromium } = await import("playwright-core");

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
        args: [...args, "--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
        executablePath,
        headless: true,
      });
    }

    const override = process.env.CHROMIUM_EXECUTABLE_PATH;
    if (override) {
      return chromium.launch({
        executablePath: override,
        headless: true,
      });
    }

    try {
      return await chromium.launch({ channel: "chrome", headless: true });
    } catch {
      try {
        return await chromium.launch({ channel: "msedge", headless: true });
      } catch {
        return chromium.launch({ headless: true });
      }
    }
  })();

  return browserPromise;
}

function isHttpUrl(raw: string): boolean {
  try {
    const u = new URL(raw);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

export async function captureScreenshot(url: string): Promise<ScreenshotCaptureResult> {
  try {
    await resolveTarget(url);

    const browser = await getBrowser();
    const page = await browser.newPage({
      viewport: VIEWPORT,
      deviceScaleFactor: 1,
      userAgent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    });

    page.on("dialog", (dialog) => dialog.dismiss().catch(() => undefined));

    // Gate only top-level http(s) navigations — do not DNS-check about:blank / assets.
    await page.route("**/*", async (route) => {
      const req = route.request();
      if (!req.isNavigationRequest() || req.frame() !== page.mainFrame()) {
        await route.continue();
        return;
      }
      const next = req.url();
      if (!isHttpUrl(next)) {
        await route.continue();
        return;
      }
      try {
        await resolveTarget(next);
        await route.continue();
      } catch {
        await route.abort("blockedbyclient");
      }
    });

    try {
      const response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 25_000 });
      if (!response) {
        return { ok: false, error: "Screenshot navigation produced no response" };
      }
      const landed = page.url();
      if (isHttpUrl(landed)) {
        try {
          await resolveTarget(landed);
        } catch {
          return { ok: false, error: "Screenshot blocked: navigation landed on a non-public address" };
        }
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
      await page.close().catch(() => undefined);
    }
  } catch (error) {
    browserPromise = null;
    const message =
      error instanceof SsrfError
        ? error.message
        : error instanceof Error
          ? error.message
          : "Screenshot capture failed";
    return { ok: false, error: message };
  }
}
