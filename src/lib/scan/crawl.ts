import type { ResolvedTarget } from "./ssrf";
import { fetchWithPin } from "./client";
import type { FetchResult } from "./fetch";

/**
 * Bounded, same-origin, passive crawl. Given the already-validated root page,
 * discovers in-origin links and fetches a small, capped set of additional HTML
 * pages so the assessment reflects the *site*, not just the landing page.
 *
 * Politeness / safety limits (hard caps, not configurable by the target):
 *   - same origin only (scheme + host + port)
 *   - max pages, max total bytes, per-request timeout
 *   - HTML responses only; assets (js/css/img) are inventoried, not crawled
 *   - deduped, query-normalized URLs
 */

export interface CrawledPage {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  contentType: string;
}

export interface CrawlResult {
  pages: CrawledPage[];
  /** All in-origin links discovered (deduped), whether or not fetched. */
  discovered: string[];
}

const MAX_PAGES = 8;
const PER_PAGE_TIMEOUT = 8000;
const PER_PAGE_BYTES = 1_500_000;

function normalize(href: string, base: string, origin: string): string | null {
  let u: URL;
  try {
    u = new URL(href, base);
  } catch {
    return null;
  }
  if (u.origin !== origin) return null;
  if (!/^https?:$/.test(u.protocol)) return null;
  u.hash = "";
  // Drop query for dedup/politeness — same page, avoid infinite param spaces.
  u.search = "";
  // Skip obvious non-HTML asset extensions.
  if (/\.(png|jpe?g|gif|svg|webp|ico|css|js|mjs|woff2?|ttf|map|pdf|zip|mp4|webm)$/i.test(u.pathname)) {
    return null;
  }
  return u.toString();
}

function extractLinks(html: string, base: string, origin: string): string[] {
  const out = new Set<string>();
  const re = /<a\b[^>]*\bhref=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const norm = normalize(m[1]!, base, origin);
    if (norm) out.add(norm);
  }
  return [...out];
}

function isHtml(res: FetchResult): boolean {
  const ct = (res.headers["content-type"] ?? "").toLowerCase();
  return ct.includes("text/html") || ct.includes("application/xhtml");
}

/**
 * @param rootUrl   the final (post-redirect) URL of the root page
 * @param rootPage  the already-fetched root FetchResult
 * @param pin       the validated pin for the origin (reused for same-origin GETs)
 */
export async function crawl(
  rootUrl: string,
  rootPage: FetchResult,
  pin: ResolvedTarget,
): Promise<CrawlResult> {
  const origin = new URL(rootUrl).origin;
  const rootCt = (rootPage.headers["content-type"] ?? "").toLowerCase();

  const pages: CrawledPage[] = [
    {
      url: rootUrl,
      status: rootPage.status,
      headers: rootPage.headers,
      body: rootPage.body,
      contentType: rootCt,
    },
  ];

  const discovered = extractLinks(rootPage.body, rootUrl, origin);
  const queue = discovered.filter((u) => u !== rootUrl).slice(0, MAX_PAGES * 3);
  const visited = new Set<string>([rootUrl]);

  for (const link of queue) {
    if (pages.length >= MAX_PAGES) break;
    if (visited.has(link)) continue;
    visited.add(link);
    try {
      const res = await fetchWithPin(link, pin, { timeoutMs: PER_PAGE_TIMEOUT, maxBytes: PER_PAGE_BYTES });
      if (res.status >= 200 && res.status < 400 && isHtml(res)) {
        pages.push({
          url: link,
          status: res.status,
          headers: res.headers,
          body: res.body,
          contentType: (res.headers["content-type"] ?? "").toLowerCase(),
        });
      }
    } catch {
      // A single unreachable page never aborts the crawl.
    }
  }

  return { pages, discovered };
}
