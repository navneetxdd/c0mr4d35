/**
 * Content-Security-Policy builders.
 * Script nonces are generated per-request in middleware (no 'unsafe-inline' on script-src).
 */

export function buildCspHeader(nonce: string, isDev: boolean): string {
  const scriptSrc = [
    "'self'",
    `'nonce-${nonce}'`,
    // Allows Next.js / webpack chunks loaded by the nonced bootstrap.
    "'strict-dynamic'",
    // React Refresh / Turbopack need eval in local dev only.
    ...(isDev ? ["'unsafe-eval'"] : []),
  ].join(" ");

  return [
    "default-src 'self'",
    `script-src ${scriptSrc}`,
    // Styles: Tailwind + runtime style attrs still need unsafe-inline; external Fontshare CSS allowed.
    "style-src 'self' 'unsafe-inline' https://api.fontshare.com",
    "font-src 'self' https://cdn.fontshare.com data:",
    "img-src 'self' data: blob: https:",
    "connect-src 'self' https://*.supabase.co wss://*.supabase.co https://crt.sh",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests",
  ].join("; ");
}
