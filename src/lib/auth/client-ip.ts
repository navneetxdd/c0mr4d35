import "server-only";

import { headers } from "next/headers";

/**
 * Client IP for rate limiting behind Vercel/proxies.
 *
 * Never trust the leftmost X-Forwarded-For hop — clients can prepend arbitrary
 * values. On Vercel prefer platform headers; otherwise use the rightmost XFF
 * entry (appended by the trusted edge).
 */
export async function getClientIp(): Promise<string> {
  const h = await headers();

  const vercelFwd = h.get("x-vercel-forwarded-for")?.split(",")[0]?.trim();
  if (vercelFwd) return vercelFwd.slice(0, 64);

  const realIp = h.get("x-real-ip")?.trim();
  if (realIp) return realIp.slice(0, 64);

  const forwarded = h.get("x-forwarded-for");
  if (forwarded) {
    const parts = forwarded
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);
    const last = parts[parts.length - 1];
    if (last) return last.slice(0, 64);
  }

  return "unknown";
}
