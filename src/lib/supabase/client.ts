"use client";

import { createBrowserClient } from "@supabase/ssr";

/**
 * Browser Supabase client — uses the anon key and the user's session cookie, so
 * every query it makes is constrained by Row Level Security. Never give this the
 * service-role key.
 */
export function createClient() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
  );
}
