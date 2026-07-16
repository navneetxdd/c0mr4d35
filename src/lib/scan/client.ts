import { resolveTarget, SsrfError, type ResolvedTarget } from "./ssrf";
import { guardedFetch, type FetchResult } from "./fetch";

/**
 * High-level scan client: resolve + SSRF-validate + pin + fetch, following
 * redirects safely. Every redirect hop is *re-resolved and re-validated*
 * through resolveTarget(), so an attacker cannot 3xx us from a public host
 * into an internal one (SSRF-via-redirect). This is the single entry point the
 * rest of the engine uses to touch the network.
 */

export interface ScanResponse {
  final: FetchResult;
  resolved: ResolvedTarget;
  /** Redirect chain (each absolute URL we followed), excluding the final. */
  chain: string[];
}

export interface FetchUrlOptions {
  method?: string;
  timeoutMs?: number;
  maxBytes?: number;
  headers?: Record<string, string>;
  followRedirects?: boolean;
  maxHops?: number;
}

/**
 * Resolve a raw target, validate it, and fetch it. Follows up to `maxHops`
 * redirects, re-validating each destination. Throws SsrfError on any target
 * that fails validation at any hop.
 */
export async function fetchUrl(raw: string, opts: FetchUrlOptions = {}): Promise<ScanResponse> {
  const maxHops = opts.maxHops ?? 4;
  const chain: string[] = [];
  let current = raw;

  for (let hop = 0; hop <= maxHops; hop++) {
    const resolved = await resolveTarget(current);
    const url = resolved.url.toString();
    const res = await guardedFetch(url, {
      method: opts.method,
      timeoutMs: opts.timeoutMs,
      maxBytes: opts.maxBytes,
      headers: opts.headers,
      pin: resolved,
    });

    const follow = opts.followRedirects ?? true;
    if (follow && res.status >= 300 && res.status < 400 && res.redirectedTo && hop < maxHops) {
      chain.push(url);
      current = res.redirectedTo;
      continue;
    }

    return { final: res, resolved, chain };
  }

  // Exhausted hops — treat as a redirect loop.
  throw new SsrfError("Too many redirects");
}

/** Fetch using an already-validated pin (same-origin, no re-resolution). Used
 *  by probes that hit many paths on a host we've already validated. */
export function fetchWithPin(
  url: string,
  pin: ResolvedTarget,
  opts: { method?: string; timeoutMs?: number; maxBytes?: number; headers?: Record<string, string> } = {},
): Promise<FetchResult> {
  return guardedFetch(url, { ...opts, pin });
}

export { SsrfError };
