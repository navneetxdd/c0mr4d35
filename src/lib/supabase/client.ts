"use client";

import { createBrowserClient } from "@supabase/ssr";
import { requireSupabaseAnonEnv } from "@/lib/supabase/env";

/**
 * Browser Supabase client — uses the anon key and the user's session cookie, so
 * every query it makes is constrained by Row Level Security. Never give this the
 * service-role key.
 */
export function createClient() {
  const { url, anonKey } = requireSupabaseAnonEnv();
  return createBrowserClient(url, anonKey);
}
