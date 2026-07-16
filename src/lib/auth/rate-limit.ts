import "server-only";
import { createAdminClient } from "@/lib/supabase/admin";

/** Returns true when the action is allowed under the fixed-window limiter. */
export async function checkRateLimit(
  key: string,
  limit: number,
  windowSeconds: number,
): Promise<boolean> {
  const admin = createAdminClient();
  const { data, error } = await admin.rpc("rate_limit_check", {
    p_key: key,
    p_limit: limit,
    p_window_seconds: windowSeconds,
  });
  if (error) return false;
  return Boolean(data);
}
