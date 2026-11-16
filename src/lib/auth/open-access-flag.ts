/**
 * TEMPORARY: login / session gate is HIDDEN (not deleted) so the console is
 * publicly usable as admin. To restore normal auth later:
 * 1. Set OPEN_CONSOLE_ACCESS to false
 * 2. Un-hide the commented blocks marked "HIDDEN (restore later)" in
 *    src/middleware.ts and src/app/login/page.tsx
 * 3. Revert createServerSupabase / getSessionProfile open-access branches
 *    in src/lib/supabase/server.ts and src/lib/auth/rbac.ts
 */
export const OPEN_CONSOLE_ACCESS = true;
