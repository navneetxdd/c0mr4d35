import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
import { OPEN_CONSOLE_ACCESS } from "@/lib/auth/open-access-flag";
import { createAdminClient } from "@/lib/supabase/admin";
import { requireSupabaseAnonEnv } from "@/lib/supabase/env";

/**
 * Server Supabase client bound to the request's session cookies. Uses the anon
 * key, so all queries are RLS-scoped to the signed-in user — this is the client
 * to use in Server Components and Server Actions for anything a user is allowed
 * to see or do. Privileged writes use the admin client instead.
 *
 * HIDDEN (restore later): when OPEN_CONSOLE_ACCESS is true, returns the
 * service-role client so the console works without a session (admin perms).
 * Set OPEN_CONSOLE_ACCESS=false and delete this branch to restore session RLS.
 */
export async function createServerSupabase() {
  // HIDDEN (restore later): open-console bypass — remove this block to restore login-scoped RLS.
  if (OPEN_CONSOLE_ACCESS) {
    return createAdminClient();
  }

  const { url, anonKey } = requireSupabaseAnonEnv();
  const cookieStore = await cookies();
  return createServerClient(url, anonKey, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        try {
          for (const { name, value, options } of cookiesToSet) {
            cookieStore.set(name, value, options);
          }
        } catch {
          // Called from a Server Component render — safe to ignore; the
          // middleware refreshes the session cookie on the response.
        }
      },
    },
  });
}
