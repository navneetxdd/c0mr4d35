import type { NextConfig } from "next";

/** Same value on server + client — avoids login hydration mismatch from VERCEL_* (server-only). */
const BUILD_HASH =
  process.env.VERCEL_GIT_COMMIT_SHA?.slice(0, 7) ||
  process.env.NEXT_PUBLIC_BUILD_HASH?.slice(0, 7) ||
  "dev-local";

/** Non-CSP headers only — Content-Security-Policy is set per-request in middleware (nonce). */
const securityHeaders = [
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  // Explicitly refuse cross-origin reads — overrides any platform ACAO: * leak.
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
];

const nextConfig: NextConfig = {
  env: {
    NEXT_PUBLIC_BUILD_HASH: BUILD_HASH,
  },
  // Local `next dev` only — never injected into production/Vercel builds.
  // Hides the bottom-left Next.js DevTools badge (not an app admin panel).
  devIndicators: false,
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
