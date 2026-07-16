import "server-only";

import { createHash } from "node:crypto";
import MurmurHash3 from "murmurhash3js-revisited";
import { fetchUrl } from "./client";

export interface FaviconResult {
  url: string | null;
  hash: string | null;
  sha256: string | null;
}

function findIconHref(html: string): string | null {
  const match = html.match(
    /<link\b[^>]*rel=["'][^"']*icon[^"']*["'][^>]*href=["']([^"']+)["'][^>]*>/i,
  );
  return match?.[1] ?? null;
}

function wrapBase64(buffer: Buffer): string {
  const base64 = buffer.toString("base64");
  const chunks = base64.match(/.{1,76}/g) ?? [base64];
  return `${chunks.join("\n")}\n`;
}

function mmh3FromBuffer(buffer: Buffer): string {
  const wrapped = wrapBase64(buffer);
  const bytes = Uint8Array.from(Buffer.from(wrapped, "utf8"));
  const value = MurmurHash3.x86.hash32(bytes);
  return String(value);
}

export async function fetchFavicon(
  html: string,
  pageUrl: string,
): Promise<FaviconResult> {
  const page = new URL(pageUrl);
  const href = findIconHref(html) ?? "/favicon.ico";
  const resolved = new URL(href, pageUrl);
  const iconUrl = resolved.origin === page.origin ? resolved.toString() : new URL("/favicon.ico", pageUrl).toString();

  try {
    const res = await fetchUrl(iconUrl, {
      timeoutMs: 5_000,
      maxBytes: 512_000,
      followRedirects: true,
      maxHops: 2,
    });
    if (res.final.status < 200 || res.final.status >= 300 || res.final.bodyBytes.length === 0) {
      return { url: iconUrl, hash: null, sha256: null };
    }

    return {
      url: res.final.finalUrl,
      hash: mmh3FromBuffer(res.final.bodyBytes),
      sha256: createHash("sha256").update(res.final.bodyBytes).digest("hex"),
    };
  } catch {
    return { url: iconUrl, hash: null, sha256: null };
  }
}
