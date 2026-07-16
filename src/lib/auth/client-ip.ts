import "server-only";

import { headers } from "next/headers";

/** Best-effort client IP for rate limiting behind Vercel/proxies. */
export async function getClientIp(): Promise<string> {
  const h = await headers();
  const forwarded = h.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first) return first.slice(0, 64);
  }
  const realIp = h.get("x-real-ip");
  if (realIp) return realIp.slice(0, 64);
  return "unknown";
}
