import { getSessionProfile } from "@/lib/auth/rbac";
import type { Profile } from "@/lib/supabase/types";

export class UnauthorizedError extends Error {
  constructor(message = "Authentication required") {
    super(message);
    this.name = "UnauthorizedError";
  }
}

/** Throws UnauthorizedError if no signed-in user. */
export async function requireUser(): Promise<Profile> {
  const profile = await getSessionProfile();
  if (!profile) throw new UnauthorizedError();
  return profile;
}

export { ForbiddenError, requireRole } from "@/lib/auth/rbac";
