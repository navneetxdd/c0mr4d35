import { GoogleGenerativeAI } from "@google/generative-ai";
import type { ScanResult } from "@/lib/scan";
import type { ScanFinding } from "@/lib/scan/risk";

/**
 * AI security verdict — BYOK per hackathon rules.
 * Provider: Google Gemini. Model: gemini-2.5-flash. Key: process.env.GEMINI_API_KEY.
 * Disclosed in README as required by the problem statement.
 *
 * Contract: FAIL-OPEN. If the key is absent or the call errors/times out, we
 * return { available: false } and the caller renders the raw findings as
 * authoritative. AI enrichment must never gate or hide real detection.
 */

export const AI_PROVIDER = "Google Gemini";
export const AI_MODEL = "gemini-2.5-flash";

export interface AiVerdict {
  available: boolean;
  verdict: "BASELINE HELD" | "DRIFT DETECTED" | "DEFACEMENT" | "AT RISK";
  confidence: number;
  summary: string;
  prioritizedRisks: { title: string; why: string }[];
  recommendedActions: string[];
  error?: string;
}

function heuristicFallback(scan: ScanResult, reason: string): AiVerdict {
  const verdict: AiVerdict["verdict"] =
    scan.posture === "critical"
      ? scan.findings.some((f) => f.category === "DEFACEMENT")
        ? "DEFACEMENT"
        : "AT RISK"
      : scan.posture === "watch"
        ? "DRIFT DETECTED"
        : "BASELINE HELD";
  return {
    available: false,
    verdict,
    confidence: 0,
    summary: "AI enrichment unavailable — findings below are authoritative.",
    prioritizedRisks: [],
    recommendedActions: [],
    error: reason,
  };
}

function buildPrompt(scan: ScanResult): string {
  const findingLines = scan.findings
    .map((f) => `- [${f.risk.toUpperCase()}] (${f.category}) ${f.title}: ${f.detail}`)
    .join("\n");
  return [
    "You are a web security analyst. Assess this automated scan of a monitored website and return STRICT JSON only.",
    "",
    `Target: ${scan.finalHost}`,
    `HTTP status: ${scan.httpStatus}`,
    `Pages assessed: ${scan.pagesScanned} (of ${scan.discoveredLinks} discovered)`,
    `Detected stack: ${scan.techStack.length ? scan.techStack.join(", ") : "unknown"}`,
    `Content drift vs baseline: ${scan.driftPct}% (changed: ${scan.contentChanged})`,
    `Severity spread: ${JSON.stringify(scan.severityCounts)}`,
    `Posture score (0-100, higher is safer): ${scan.postureScore}`,
    "",
    "Findings:",
    findingLines || "- none",
    "",
    "Return JSON with this exact shape:",
    `{"verdict":"BASELINE HELD|DRIFT DETECTED|DEFACEMENT|AT RISK","confidence":0.0-1.0,"summary":"one sentence","prioritizedRisks":[{"title":"...","why":"..."}],"recommendedActions":["..."]}`,
    "Prioritize by real-world impact. Do not invent findings not present above. Keep summary under 240 chars.",
  ].join("\n");
}

export async function getAiVerdict(scan: ScanResult): Promise<AiVerdict> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return heuristicFallback(scan, "GEMINI_API_KEY not configured");

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({
      model: AI_MODEL,
      generationConfig: { responseMimeType: "application/json", temperature: 0.2 },
    });

    const result = await Promise.race([
      model.generateContent(buildPrompt(scan)),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), 12_000)),
    ]);

    const text = result.response.text();
    const parsed = JSON.parse(text) as Partial<AiVerdict>;

    return {
      available: true,
      verdict: parsed.verdict ?? "AT RISK",
      confidence: clamp(parsed.confidence ?? 0.6),
      summary: (parsed.summary ?? "Assessment complete.").slice(0, 280),
      prioritizedRisks: Array.isArray(parsed.prioritizedRisks) ? parsed.prioritizedRisks.slice(0, 6) : [],
      recommendedActions: Array.isArray(parsed.recommendedActions) ? parsed.recommendedActions.slice(0, 6) : [],
    };
  } catch (err) {
    return heuristicFallback(scan, err instanceof Error ? err.message : "AI call failed");
  }
}

function clamp(n: number): number {
  if (Number.isNaN(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

export type { ScanFinding };
