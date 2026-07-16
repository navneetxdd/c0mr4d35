import type { ScanResult } from "@/lib/scan";
import type { AiVerdict } from "@/lib/ai/gemini";

/** Response contract for POST /api/scan (html stripped server-side). */
export type SafeScanResult = Omit<ScanResult, "html">;

export interface ScanApiSuccess {
  ok: true;
  scan: SafeScanResult;
  verdict?: AiVerdict;
}

export interface ScanApiFailure {
  ok: false;
  error: string;
  issues?: Record<string, string[] | undefined>;
}

export type ScanApiResponse = ScanApiSuccess | ScanApiFailure;
