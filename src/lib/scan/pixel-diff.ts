import "server-only";

import { PNG } from "pngjs";
import pixelmatch from "pixelmatch";

export interface PixelDiffResult {
  driftPct: number;
  diffPng: Buffer;
}

export function diffScreenshots(
  baselinePng: Buffer,
  currentPng: Buffer,
): PixelDiffResult | null {
  const baseline = PNG.sync.read(baselinePng);
  const current = PNG.sync.read(currentPng);

  if (baseline.width !== current.width || baseline.height !== current.height) {
    return null;
  }

  const diff = new PNG({ width: baseline.width, height: baseline.height });
  const mismatched = pixelmatch(
    baseline.data,
    current.data,
    diff.data,
    baseline.width,
    baseline.height,
    {
      threshold: 0.12,
      alpha: 0.7,
      includeAA: false,
    },
  );

  const totalPixels = baseline.width * baseline.height;
  const driftPct = totalPixels > 0 ? Math.round((mismatched / totalPixels) * 1000) / 10 : 0;

  return {
    driftPct,
    diffPng: PNG.sync.write(diff),
  };
}
