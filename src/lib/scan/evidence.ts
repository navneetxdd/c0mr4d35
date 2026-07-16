import "server-only";

import type { SupabaseClient } from "@supabase/supabase-js";
import type { ScanFinding } from "./risk";
import { captureScreenshot } from "./screenshot";
import { diffScreenshots } from "./pixel-diff";
import { fetchFavicon } from "./favicon";
import {
  createEvidenceSignedUrl,
  downloadEvidenceBuffer,
  uploadEvidenceBuffer,
} from "./evidence-storage";
export interface EvidenceBaseline {
  screenshotPath?: string | null;
  faviconHash?: string | null;
}

export interface ScanEvidence {
  visualDriftPct: number | null;
  screenshotPath: string | null;
  baselineScreenshotPath: string | null;
  diffPath: string | null;
  screenshotUrl: string | null;
  baselineScreenshotUrl: string | null;
  diffUrl: string | null;
  faviconHash: string | null;
  faviconChanged: boolean;
  faviconUrl: string | null;
  notes: string[];
  extraFindings: ScanFinding[];
}

export async function collectScanEvidence(opts: {
  admin: SupabaseClient;
  storageBasePath: string;
  targetUrl: string;
  html: string;
  baseline?: EvidenceBaseline | null;
}): Promise<ScanEvidence> {
  const notes: string[] = [];
  const extraFindings: ScanFinding[] = [];

  const screenshot = await captureScreenshot(opts.targetUrl);
  let screenshotPath: string | null = null;
  let diffPath: string | null = null;
  let visualDriftPct: number | null = null;

  try {
    if (!screenshot.ok || !screenshot.png) {
      notes.push(`Screenshot capture unavailable: ${screenshot.error ?? "unknown error"}`);
    } else {
      screenshotPath = await uploadEvidenceBuffer(
        opts.admin,
        `${opts.storageBasePath}/current.png`,
        screenshot.png,
        "image/png",
      );

      const baselineBytes = await downloadEvidenceBuffer(opts.admin, opts.baseline?.screenshotPath);
      if (baselineBytes) {
        const pixelDiff = diffScreenshots(baselineBytes, screenshot.png);
        if (pixelDiff) {
          visualDriftPct = pixelDiff.driftPct;
          diffPath = await uploadEvidenceBuffer(
            opts.admin,
            `${opts.storageBasePath}/diff.png`,
            pixelDiff.diffPng,
            "image/png",
          );
        } else {
          notes.push("Visual diff skipped because baseline and current screenshots differ in size.");
        }
      }
    }
  } catch (error) {
    notes.push(
      `Visual evidence unavailable: ${error instanceof Error ? error.message : "storage failure"}`,
    );
  }

  const favicon = await fetchFavicon(opts.html, opts.targetUrl);
  const faviconChanged =
    Boolean(opts.baseline?.faviconHash) &&
    Boolean(favicon.hash) &&
    opts.baseline?.faviconHash !== favicon.hash;

  if (faviconChanged) {
    extraFindings.push({
      id: "favicon-identity-changed",
      category: "BEHAVIOR",
      risk: "medium",
      title: "Favicon identity changed",
      detail:
        "The site's favicon fingerprint no longer matches the stored baseline. Unexpected icon changes can accompany spoofing, takeover, or defacement.",
      remediation: "Confirm the favicon change is intentional; if not, investigate for unauthorized content or branding changes.",
      evidence: `baseline=${opts.baseline?.faviconHash} current=${favicon.hash}`,
      owasp: "A08:2021 Software and Data Integrity Failures",
      cwe: "CWE-353",
      url: favicon.url ?? opts.targetUrl,
    });
  }

  let screenshotUrl: string | null = null;
  let baselineScreenshotUrl: string | null = null;
  let diffUrl: string | null = null;
  try {
    [screenshotUrl, baselineScreenshotUrl, diffUrl] = await Promise.all([
      createEvidenceSignedUrl(opts.admin, screenshotPath),
      createEvidenceSignedUrl(opts.admin, opts.baseline?.screenshotPath ?? null),
      createEvidenceSignedUrl(opts.admin, diffPath),
    ]);
  } catch (error) {
    notes.push(
      `Signed evidence URLs unavailable: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }

  return {
    visualDriftPct,
    screenshotPath,
    baselineScreenshotPath: opts.baseline?.screenshotPath ?? null,
    diffPath,
    screenshotUrl,
    baselineScreenshotUrl,
    diffUrl,
    faviconHash: favicon.hash,
    faviconChanged,
    faviconUrl: favicon.url,
    notes,
    extraFindings,
  };
}
