/**
 * Single source for public Supabase env. Never call create*Client with
 * undefined/empty strings — @supabase/ssr throws a cryptic runtime error.
 */
export function getSupabaseAnonEnv(): { url: string; anonKey: string } {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL?.trim() ?? "";
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY?.trim() ?? "";
  return { url, anonKey };
}

export function requireSupabaseAnonEnv(): { url: string; anonKey: string } {
  const { url, anonKey } = getSupabaseAnonEnv();
  if (!url || !anonKey) {
    throw new Error(
      "Missing NEXT_PUBLIC_SUPABASE_URL or NEXT_PUBLIC_SUPABASE_ANON_KEY. Set them in .env.local (see .env.example) and restart `npm run dev`.",
    );
  }
  return { url, anonKey };
}

export function isSupabaseConfigured(): boolean {
  const { url, anonKey } = getSupabaseAnonEnv();
  return Boolean(url && anonKey);
}
