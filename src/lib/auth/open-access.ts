import "server-only";

import { OPEN_CONSOLE_ACCESS } from "@/lib/auth/open-access-flag";
import { createAdminClient } from "@/lib/supabase/admin";
import type { Profile } from "@/lib/supabase/types";

export { OPEN_CONSOLE_ACCESS };

const FALLBACK_ADMIN: Profile = {
  id: "00000000-0000-4000-8000-0000000000ad",
  email: "open-access@datum.local",
  role: "admin",
  created_at: "1970-01-01T00:00:00.000Z",
};

/** Highest role (admin). Prefers a real profiles row so FKs (owner, requested_by) succeed. */
export async function resolveOpenAccessAdmin(): Promise<Profile> {
  try {
    const admin = createAdminClient();
    const { data: adminRow } = await admin
      .from("profiles")
      .select("*")
      .eq("role", "admin")
      .order("created_at", { ascending: true })
      .limit(1)
      .maybeSingle();
    if (adminRow) return adminRow as Profile;

    const { data: anyRow } = await admin
      .from("profiles")
      .select("*")
      .order("created_at", { ascending: true })
      .limit(1)
      .maybeSingle();
    if (anyRow) {
      return { ...(anyRow as Profile), role: "admin" };
    }
  } catch {
    // Service role missing or DB unreachable — fall through.
  }
  return FALLBACK_ADMIN;
}
