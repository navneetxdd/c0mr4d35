import type { NextConfig } from "next";

/** Same value on server + client — avoids login hydration mismatch from VERCEL_* (server-only). */
const BUILD_HASH =
  process.env.VERCEL_GIT_COMMIT_SHA?.slice(0, 7) ||
  process.env.NEXT_PUBLIC_BUILD_HASH?.slice(0, 7) ||
  "dev-local";

const securityHeaders = [
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline' https://api.fontshare.com",
      "font-src 'self' https://cdn.fontshare.com data:",
      "img-src 'self' data: blob: https:",
      "connect-src 'self' https://*.supabase.co wss://*.supabase.co https://crt.sh",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; "),
  },
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];

const nextConfig: NextConfig = {
  env: {
    NEXT_PUBLIC_BUILD_HASH: BUILD_HASH,
  },
  turbopack: {
    root: process.cwd(),
  },
  // chromium-min has no local bin/; it downloads a remote pack at runtime on Vercel.
  serverExternalPackages: ["playwright-core", "@sparticuz/chromium-min"],
  async headers() {
    return [
      { source: "/:path*", headers: securityHeaders },
      {
        source: "/login",
        headers: [{ key: "Cache-Control", value: "no-store, max-age=0" }],
      },
    ];
  },
};

export default nextConfig;
