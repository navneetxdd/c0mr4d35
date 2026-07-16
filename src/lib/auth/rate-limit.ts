import "server-only";
import { createAdminClient } from "@/lib/supabase/admin";

/** Returns true when the action is allowed under the fixed-window limiter. */
export async function checkRateLimit(
  key: string,
  limit: number,
  windowSeconds: number,
): Promise<boolean> {
  // Service role is required for the RPC. Without it (fresh clone), fail-open in
  // development so signup/login still work; fail-closed in production.
  if (!process.env.SUPABASE_SERVICE_ROLE_KEY?.trim()) {
    return process.env.NODE_ENV !== "production";
  }

  try {
    const admin = createAdminClient();
    const { data, error } = await admin.rpc("rate_limit_check", {
      p_key: key,
      p_limit: limit,
      p_window_seconds: windowSeconds,
    });
    if (error) return false;
    return Boolean(data);
  } catch {
    return process.env.NODE_ENV !== "production";
  }
}
