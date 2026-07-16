import "server-only";

import { chromium, type Browser } from "playwright";

const VIEWPORT = { width: 1440, height: 900 };

export interface ScreenshotCaptureResult {
  ok: boolean;
  png?: Buffer;
  error?: string;
}

let browserPromise: Promise<Browser> | null = null;

async function getBrowser(): Promise<Browser> {
  if (!browserPromise) {
    browserPromise = chromium.launch({ headless: true });
  }
  return browserPromise;
}

export async function captureScreenshot(url: string): Promise<ScreenshotCaptureResult> {
  try {
    const browser = await getBrowser();
    const page = await browser.newPage({
      viewport: VIEWPORT,
      deviceScaleFactor: 1,
      userAgent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    });

    page.on("dialog", (dialog) => dialog.dismiss().catch(() => undefined));

    try {
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: 20_000 });
      await page.waitForLoadState("networkidle", { timeout: 5_000 }).catch(() => undefined);
      await page.addStyleTag({
        content:
          "*,:before,:after{animation:none!important;transition:none!important;caret-color:transparent!important}",
      }).catch(() => undefined);
      const png = await page.screenshot({ type: "png", animations: "disabled" });
      return { ok: true, png };
    } finally {
      await page.close().catch(() => undefined);
    }
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : "Screenshot capture failed",
    };
  }
}
