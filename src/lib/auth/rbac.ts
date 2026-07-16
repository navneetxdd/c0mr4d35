import { createServerSupabase } from "@/lib/supabase/server";
import { ROLE_RANK, type AppRole, type Profile } from "@/lib/supabase/types";

/**
 * Server-side RBAC. This is the SECOND gate on top of Row Level Security — RLS
 * is the authoritative enforcement at the database, and these helpers let
 * Server Actions / route handlers fail fast and clearly before touching the DB.
 * Never rely on a hidden UI control as the access boundary.
 */

export async function getSessionProfile(): Promise<Profile | null> {
  const supabase = await createServerSupabase();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return null;
  const { data } = await supabase.from("profiles").select("*").eq("id", user.id).single();
  return (data as Profile | null) ?? null;
}

export function hasRole(role: AppRole | undefined | null, min: AppRole): boolean {
  if (!role) return false;
  return ROLE_RANK[role] >= ROLE_RANK[min];
}

export class ForbiddenError extends Error {
  constructor(message = "Insufficient permissions") {
    super(message);
    this.name = "ForbiddenError";
  }
}

/** Throws ForbiddenError if the caller isn't signed in with at least `min`. */
export async function requireRole(min: AppRole): Promise<Profile> {
  const profile = await getSessionProfile();
  if (!profile || !hasRole(profile.role, min)) {
    throw new ForbiddenError();
  }
  return profile;
}
