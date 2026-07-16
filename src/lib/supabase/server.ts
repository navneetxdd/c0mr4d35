import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

/**
 * Server Supabase client bound to the request's session cookies. Uses the anon
 * key, so all queries are RLS-scoped to the signed-in user — this is the client
 * to use in Server Components and Server Actions for anything a user is allowed
 * to see or do. Privileged writes use the admin client instead.
 */
export async function createServerSupabase() {
  const cookieStore = await cookies();
  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
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
    },
  );
}
