import { createHash } from "node:crypto";

/**
 * Content-based defacement detection. We canonicalize the HTML so that
 * benign, non-defacement noise (whitespace, CSRF tokens, timestamps, session
 * ids, cache-busting query strings, nonces) does not register as drift, then
 * hash the normalized document. Comparison against the stored baseline hash
 * yields a boolean "content changed", and a token-level diff yields a drift %.
 */

const NOISE_PATTERNS: { re: RegExp; replace: string }[] = [
  { re: /<!--[\s\S]*?-->/g, replace: "" }, // comments
  { re: /<script\b[^>]*>[\s\S]*?<\/script>/gi, replace: "\u0001SCRIPT\u0001" },
  { re: /<style\b[^>]*>[\s\S]*?<\/style>/gi, replace: "\u0001STYLE\u0001" },
  { re: /(name=["']?(csrf|_token|authenticity_token|__RequestVerificationToken)["']?[^>]*value=["'])[^"']*(["'])/gi, replace: "$1\u0001TOKEN\u0001$3" },
  { re: /(nonce=["'])[^"']*(["'])/gi, replace: "$1\u0001NONCE\u0001$2" },
  { re: /\b[0-9a-f]{32,64}\b/gi, replace: "\u0001HEX\u0001" }, // hashes / session ids
  { re: /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?\b/g, replace: "\u0001TS\u0001" },
  { re: /\?[a-z0-9_]+=[^"'\s>]+/gi, replace: "?\u0001QS\u0001" }, // cache-busting query strings
  { re: /\s+/g, replace: " " },
];

export function canonicalizeHtml(html: string): string {
  let out = html;
  for (const { re, replace } of NOISE_PATTERNS) {
    out = out.replace(re, replace);
  }
  return out.trim().toLowerCase();
}

export function domHash(html: string): string {
  return createHash("sha256").update(canonicalizeHtml(html), "utf8").digest("hex");
}

/** Extracts visible-ish text tokens for a coarse structural diff. */
function tokenize(html: string): string[] {
  const text = canonicalizeHtml(html)
    .replace(/<[^>]+>/g, " ")
    .replace(/\u0001[a-z]+\u0001/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
  return text.length ? text.split(" ") : [];
}

export interface DomDiff {
  currentHash: string;
  changed: boolean;
  driftPct: number;
}

/**
 * Jaccard-distance drift between baseline and current token multisets.
 * 0% == identical content, 100% == no overlap. Robust to reordering and
 * insignificant of the noise stripped above.
 */
export function diffDom(baselineHtml: string, currentHtml: string): DomDiff {
  const currentHash = domHash(currentHtml);
  const baseHash = domHash(baselineHtml);
  if (currentHash === baseHash) {
    return { currentHash, changed: false, driftPct: 0 };
  }

  const a = new Set(tokenize(baselineHtml));
  const b = new Set(tokenize(currentHtml));
  if (a.size === 0 && b.size === 0) {
    return { currentHash, changed: true, driftPct: 0 };
  }

  let intersection = 0;
  for (const t of a) if (b.has(t)) intersection += 1;
  const union = a.size + b.size - intersection;
  const similarity = union === 0 ? 1 : intersection / union;
  const driftPct = Math.round((1 - similarity) * 1000) / 10;

  return { currentHash, changed: true, driftPct };
}
