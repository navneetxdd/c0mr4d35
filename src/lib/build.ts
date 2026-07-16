/**
 * Build identifier for login/settings.
 * Must come from NEXT_PUBLIC_BUILD_HASH (set in next.config from VERCEL_GIT_COMMIT_SHA)
 * so SSR HTML and the client bundle always agree — VERCEL_* alone causes React #418.
 */
export const BUILD_HASH = process.env.NEXT_PUBLIC_BUILD_HASH?.slice(0, 7) ?? "dev-local";
