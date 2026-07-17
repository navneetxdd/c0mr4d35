import type { ScanResult } from "@/lib/scan";
import type { ScanFinding } from "@/lib/scan/risk";

/**
 * AI security verdict — BYOK per hackathon rules.
 * Provider: Google Gemini. Model: gemini-2.5-flash.
 * Native Generative Language REST + x-goog-api-key (AIza… and AQ.… auth keys).
 *
 * FAIL-OPEN: missing key / errors / timeouts never hide engine findings.
 */

export const AI_PROVIDER = "Google Gemini";
export const AI_MODEL = "gemini-2.5-flash";

const GEMINI_ENDPOINT = `https://generativelanguage.googleapis.com/v1beta/models/${AI_MODEL}:generateContent`;
/** Generous budget — Vercel scans often leave AI until the end; 12s was causing false timeouts. */
const AI_TIMEOUT_MS = 45_000;
const MAX_FINDINGS_IN_PROMPT = 18;

export interface AiVerdict {
  available: boolean;
  verdict: "BASELINE HELD" | "DRIFT DETECTED" | "DEFACEMENT" | "AT RISK";
  confidence: number;
  summary: string;
  prioritizedRisks: { title: string; why: string }[];
  recommendedActions: string[];
  error?: string;
}

const RISK_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function heuristicFallback(scan: ScanResult, reason: string): AiVerdict {
  const hasDeface = scan.findings.some((f) => f.category === "DEFACEMENT");
  const verdict: AiVerdict["verdict"] =
    scan.defacement?.classification === "DEFACEMENT" || hasDeface
      ? "DEFACEMENT"
      : scan.posture === "critical"
        ? "AT RISK"
        : scan.posture === "watch" || (scan.defacement?.score ?? 0) >= 20
          ? "DRIFT DETECTED"
          : "BASELINE HELD";

  const ranked = [...scan.findings].sort(
    (a, b) => (RISK_RANK[a.risk] ?? 9) - (RISK_RANK[b.risk] ?? 9),
  );
  const prioritizedRisks = ranked.slice(0, 3).map((f) => ({
    title: f.title,
    why: f.detail.slice(0, 160),
  }));
  const recommendedActions = ranked
    .slice(0, 3)
    .map((f) => f.remediation)
    .filter(Boolean)
    .slice(0, 3);

  const confBoost = scan.defacement ? Math.min(0.55, scan.defacement.score / 100) : 0.25;

  return {
    available: false,
    verdict,
    confidence: confBoost,
    summary:
      scan.defacement != null
        ? `Heuristic triage — defacement confidence ${scan.defacement.score}/100 (${scan.defacement.layersFired} layers). Engine findings remain authoritative.`
        : "AI enrichment unavailable — findings below are authoritative.",
    prioritizedRisks,
    recommendedActions,
    error: reason,
  };
}

function buildPrompt(scan: ScanResult): string {
  const ranked = [...scan.findings].sort(
    (a, b) => (RISK_RANK[a.risk] ?? 9) - (RISK_RANK[b.risk] ?? 9),
  );
  const top = ranked.slice(0, MAX_FINDINGS_IN_PROMPT);
  const findingLines = top
    .map((f) => `- [${f.risk.toUpperCase()}] (${f.category}) ${f.title}: ${f.detail.slice(0, 220)}`)
    .join("\n");
  const omitted = Math.max(0, scan.findings.length - top.length);

  const visual =
    scan.visualDriftPct == null ? "n/a" : `${scan.visualDriftPct}%`;
  const deface = scan.defacement;
  const defaceLine = deface
    ? `Defacement confidence: ${deface.score}/100 (${deface.classification}, ${deface.layersFired} layers fired: ${deface.layers
        .filter((l) => l.fired)
        .map((l) => `${l.id}=${l.score}`)
        .join(", ") || "none"})`
    : "Defacement confidence: not computed";

  return [
    "You are a web security analyst. Assess this automated scan and return STRICT JSON only.",
    "",
    `Target: ${scan.finalHost}`,
    `HTTP status: ${scan.httpStatus}`,
    `Pages assessed: ${scan.pagesScanned} (of ${scan.discoveredLinks} discovered)`,
    `Detected stack: ${scan.techStack.length ? scan.techStack.join(", ") : "unknown"}`,
    `Content drift vs baseline: ${scan.driftPct}% (changed: ${scan.contentChanged})`,
    `Visual pixel drift vs baseline: ${visual}`,
    `Favicon changed: ${scan.faviconChanged === true ? "yes" : scan.faviconChanged === false ? "no" : "n/a"}`,
    defaceLine,
    `Severity spread: ${JSON.stringify(scan.severityCounts)}`,
    `Posture score (0-100, higher is safer): ${scan.postureScore}`,
    "",
    "Findings (highest severity first). These are AUTHORITATIVE and already carry severity labels:",
    findingLines || "- none",
    omitted ? `(${omitted} lower-severity findings omitted from prompt)` : "",
    "",
    "Your job is to ADD analysis the finding list cannot convey on its own — not to restate it.",
    "Rules:",
    "- Do NOT repeat finding titles/descriptions verbatim, and do NOT restate every finding.",
    "- Do NOT invent findings, and do NOT change or upgrade the severities shown above (e.g. a HIGH finding is not 'CRITICAL').",
    "- prioritizedRisks: at most the 3 most consequential, where 'why' explains real-world exploitability and how issues combine into an attack chain — insight beyond the title.",
    "- recommendedActions: a concise, de-duplicated, ordered fix plan (highest-leverage first), NOT one action per finding.",
    "- summary: one sentence synthesizing overall exposure and the single most important thing to address first.",
    "- Weight multi-signal defacement confidence when present.",
    "",
    "Return JSON with this exact shape:",
    `{"verdict":"BASELINE HELD|DRIFT DETECTED|DEFACEMENT|AT RISK","confidence":0.0-1.0,"summary":"one sentence","prioritizedRisks":[{"title":"...","why":"..."}],"recommendedActions":["..."]}`,
    "Keep summary under 240 chars.",
  ]
    .filter(Boolean)
    .join("\n");
}

function explainGeminiHttpError(status: number, body: string): string {
  let detail = "";
  try {
    const parsed = JSON.parse(body) as { error?: { message?: string; status?: string } };
    detail = (parsed.error?.message ?? parsed.error?.status ?? "").slice(0, 160);
  } catch {
    detail = "";
  }
  if (status === 400 && /API_KEY_INVALID|API key not valid/i.test(detail)) {
    return "Gemini rejected the API key (invalid or revoked). Create a new key at aistudio.google.com/apikey.";
  }
  if (status === 401 || status === 403) {
    return `Gemini auth failed (HTTP ${status}). Confirm the key is from Google AI Studio.`;
  }
  if (status === 429) {
    return "Gemini rate limited or quota exhausted — retry later.";
  }
  return `Gemini HTTP ${status}${detail ? `: ${detail}` : ""}`;
}

function isAbortError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  return err.name === "AbortError" || /aborted|timeout/i.test(err.message);
}

/** Pull a JSON object out of model text (fences, prose wrapping, trailing junk). */
function extractJsonObject(raw: string): string {
  let text = raw.trim();
  const fenced = /^```(?:json)?\s*([\s\S]*?)```$/i.exec(text);
  if (fenced?.[1]) text = fenced[1].trim();
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start >= 0 && end > start) return text.slice(start, end + 1);
  return text;
}

function parseVerdictJson(raw: string): Partial<AiVerdict> {
  const candidate = extractJsonObject(raw);
  try {
    return JSON.parse(candidate) as Partial<AiVerdict>;
  } catch (err) {
    const detail = err instanceof Error ? err.message : "JSON parse failed";
    throw new Error(`Gemini returned unusable JSON (${detail})`);
  }
}

async function generateGeminiJson(
  apiKey: string,
  prompt: string,
  maxOutputTokens: number,
): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), AI_TIMEOUT_MS);
  try {
    const res = await fetch(GEMINI_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": apiKey,
      },
      body: JSON.stringify({
        contents: [{ role: "user", parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.2,
          responseMimeType: "application/json",
          maxOutputTokens,
        },
      }),
      signal: controller.signal,
    });

    const bodyText = await res.text();

    if (!res.ok) {
      throw new Error(explainGeminiHttpError(res.status, bodyText));
    }

    const payload = JSON.parse(bodyText) as {
      candidates?: Array<{
        finishReason?: string;
        content?: { parts?: Array<{ text?: string }> };
      }>;
    };
    const candidate = payload.candidates?.[0];
    const text = candidate?.content?.parts?.map((p) => p.text ?? "").join("") ?? "";
    if (!text.trim()) {
      throw new Error("Gemini returned an empty response");
    }
    if (candidate?.finishReason === "MAX_TOKENS") {
      throw new Error("Gemini response truncated (MAX_TOKENS)");
    }
    return text;
  } finally {
    clearTimeout(timer);
  }
}

function compactPrompt(scan: ScanResult): string {
  return [
    buildPrompt(scan),
    "",
    "CONSTRAINTS: summary ≤ 120 chars; at most 3 prioritizedRisks; at most 3 recommendedActions; valid JSON only.",
  ].join("\n");
}

export async function getAiVerdict(scan: ScanResult, apiKeyOverride?: string | null): Promise<AiVerdict> {
  const apiKey = apiKeyOverride?.trim() || process.env.GEMINI_API_KEY?.trim();
  if (!apiKey) return heuristicFallback(scan, "Gemini API key not configured — add one in Settings");

  try {
    const attempt = async (prompt: string) => parseVerdictJson(await generateGeminiJson(apiKey, prompt, 2048));

    let parsed: Partial<AiVerdict>;
    try {
      parsed = await attempt(buildPrompt(scan));
    } catch (firstErr) {
      const msg = firstErr instanceof Error ? firstErr.message : "";
      if (/truncated|MAX_TOKENS|unusable JSON|Unterminated string|Unexpected token/i.test(msg)) {
        parsed = await attempt(compactPrompt(scan));
      } else {
        throw firstErr;
      }
    }

    return {
      available: true,
      verdict: parsed.verdict ?? "AT RISK",
      confidence: clamp(parsed.confidence ?? 0.6),
      summary: (parsed.summary ?? "Assessment complete.").slice(0, 280),
      prioritizedRisks: Array.isArray(parsed.prioritizedRisks) ? parsed.prioritizedRisks.slice(0, 6) : [],
      recommendedActions: Array.isArray(parsed.recommendedActions)
        ? parsed.recommendedActions.slice(0, 6)
        : [],
    };
  } catch (err) {
    const reason = isAbortError(err)
      ? `timeout after ${AI_TIMEOUT_MS / 1000}s — retry scan; Gemini was too slow`
      : err instanceof Error
        ? err.message
        : "AI call failed";
    return heuristicFallback(scan, reason);
  }
}

function clamp(n: number): number {
  if (Number.isNaN(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

export type { ScanFinding };
