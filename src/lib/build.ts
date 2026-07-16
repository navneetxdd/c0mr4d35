/** Build identifier surfaced in login/settings — not fixture data. */
export const BUILD_HASH = process.env.VERCEL_GIT_COMMIT_SHA?.slice(0, 7) ?? "dev-local";
