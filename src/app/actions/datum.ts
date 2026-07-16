"use server";

import { revalidatePath } from "next/cache";
import { createAdminClient } from "@/lib/supabase/admin";
import { createServerSupabase } from "@/lib/supabase/server";
import { ForbiddenError, requireRole } from "@/lib/auth/require";
import { checkRateLimit } from "@/lib/auth/rate-limit";
import { executeScanForAsset } from "@/lib/scan/persist";
import type { AppRole, Profile } from "@/lib/supabase/types";

/** Analyst may only mutate assets they own; admin may touch any. */
async function requireAssetAccess(profile: Profile, assetId: string): Promise<{ ok: true } | { ok: false; error: string }> {
  const supabase = await createServerSupabase();
  const { data: asset, error } = await supabase.from("assets").select("owner").eq("id", assetId).maybeSingle();
  if (error) return { ok: false, error: error.message };
  if (!asset) return { ok: false, error: "Not found" };
  if (profile.role !== "admin" && asset.owner !== profile.id) {
    throw new ForbiddenError();
  }
  return { ok: true };
}

async function enforceScanRateLimit(userId: string): Promise<boolean> {
  return checkRateLimit(`scan:user:${userId}`, 10, 600);
}
export async function createAssetAndBaseline(input: {
  name: string;
  url: string;
  scanIntervalMin: number;
}) {
  const profile = await requireRole("analyst");
  const supabase = await createServerSupabase();

  let normalized = input.url.trim();
  if (!normalized.includes("://")) normalized = `https://${normalized}`;

  const { data: asset, error } = await supabase
    .from("assets")
    .insert({
      name: input.name.trim(),
      url: normalized,
      scan_interval_min: input.scanIntervalMin,
      monitoring_enabled: true,
      owner: profile.id,
    })
    .select("*")
    .single();

  if (error || !asset) {
    return { ok: false as const, error: error?.message ?? "Could not create asset" };
  }

  await supabase.from("scan_jobs").insert({
    asset_id: asset.id,
    trigger: "manual",
    requested_by: profile.id,
  });

  const result = await executeScanForAsset({
    assetId: asset.id,
    trigger: "manual",
    userId: profile.id,
    establishBaseline: true,
  });

  revalidatePath("/");
  revalidatePath("/assets");
  revalidatePath(`/assets/${asset.id}`);

  if (!result.ok) {
    return { ok: false as const, error: result.error ?? "Baseline scan failed" };
  }
  return { ok: true as const, assetId: asset.id };
}

export async function triggerAssetScan(assetId: string) {
  const profile = await requireRole("analyst");
  if (!(await enforceScanRateLimit(profile.id))) {
    return { ok: false as const, error: "Rate limit exceeded" };
  }
  const access = await requireAssetAccess(profile, assetId);
  if (!access.ok) return { ok: false as const, error: access.error };

  const supabase = await createServerSupabase();

  await supabase.from("scan_jobs").insert({
    asset_id: assetId,
    trigger: "manual",
    requested_by: profile.id,
  });

  const result = await executeScanForAsset({
    assetId,
    trigger: "manual",
    userId: profile.id,
    establishBaseline: false,
  });

  revalidatePath("/");
  revalidatePath("/assets");
  revalidatePath(`/assets/${assetId}`);
  revalidatePath("/incidents");

  if (!result.ok) return { ok: false as const, error: result.error };
  return { ok: true as const, scanId: result.scanId };
}

export async function rebaselineAsset(assetId: string) {
  const profile = await requireRole("analyst");
  if (!(await enforceScanRateLimit(profile.id))) {
    return { ok: false as const, error: "Rate limit exceeded" };
  }
  const access = await requireAssetAccess(profile, assetId);
  if (!access.ok) return { ok: false as const, error: access.error };

  const result = await executeScanForAsset({
    assetId,
    trigger: "manual",
    userId: profile.id,
    establishBaseline: true,
  });
  revalidatePath(`/assets/${assetId}`);
  if (!result.ok) return { ok: false as const, error: result.error };
  return { ok: true as const };
}

export async function updateIncidentStatus(id: string, status: "open" | "acknowledged" | "resolved") {
  await requireRole("analyst");
  const supabase = await createServerSupabase();
  const { error } = await supabase.from("incidents").update({ status }).eq("id", id);
  if (error) return { ok: false as const, error: error.message };
  revalidatePath("/incidents");
  return { ok: true as const };
}

export async function updateMemberRole(userId: string, role: AppRole) {
  await requireRole("admin");
  const supabase = await createServerSupabase();
  const { error } = await supabase.from("profiles").update({ role }).eq("id", userId);
  if (error) return { ok: false as const, error: error.message };
  revalidatePath("/members");
  return { ok: true as const };
}

export async function verifyAuditChain(): Promise<{ ok: boolean; message: string }> {
  await requireRole("admin");
  const admin = createAdminClient();
  const { data, error } = await admin.from("audit_log").select("seq, prev_hash, this_hash").order("seq", { ascending: true });
  if (error) return { ok: false, message: error.message };
  if (!data?.length) return { ok: true, message: "CHAIN EMPTY — NO ENTRIES YET" };

  for (let i = 1; i < data.length; i += 1) {
    const prev = data[i - 1];
    const cur = data[i];
    if (!prev || !cur) return { ok: false, message: "CHAIN BROKEN — MISSING ROW" };
    if (cur.prev_hash !== prev.this_hash) {
      return { ok: false, message: `CHAIN BROKEN AT SEQ ${cur.seq}` };
    }
  }
  return { ok: true, message: `CHAIN INTACT — ${data.length.toLocaleString()} ENTRIES VERIFIED` };
}

export async function signOutAction() {
  const supabase = await createServerSupabase();
  await supabase.auth.signOut();
}

export async function scanAllAssetsAction() {
  const profile = await requireRole("analyst");
  if (!(await enforceScanRateLimit(profile.id))) {
    return { ok: false as const, error: "Rate limit exceeded" };
  }
  const supabase = await createServerSupabase();
  let query = supabase.from("assets").select("id").eq("monitoring_enabled", true);
  if (profile.role !== "admin") {
    query = query.eq("owner", profile.id);
  }
  const { data: assets, error: assetsErr } = await query;

  if (assetsErr) {
    return { ok: false as const, error: assetsErr.message };
  }

  const assetIds = assets?.map((a) => a.id).filter(Boolean) ?? [];
  if (!assetIds.length) return { ok: true as const, count: 0 };

  // Avoid enqueuing duplicate jobs for the same asset.
  const { data: existingJobs, error: jobsErr } = await supabase
    .from("scan_jobs")
    .select("asset_id,status")
    .in("asset_id", assetIds)
    .in("status", ["pending", "leased"]);

  if (jobsErr) {
    return { ok: false as const, error: jobsErr.message };
  }

  const queuedSet = new Set((existingJobs ?? []).map((j) => j.asset_id));
  const toEnqueue = assetIds.filter((id) => !queuedSet.has(id));
  if (!toEnqueue.length) return { ok: true as const, count: 0 };

  const rows = toEnqueue.map((assetId) => ({
    asset_id: assetId,
    trigger: "manual",
    requested_by: profile.id,
  }));

  const { error: insertErr } = await supabase.from("scan_jobs").insert(rows);
  if (insertErr) {
    return { ok: false as const, error: insertErr.message };
  }

  revalidatePath("/");
  revalidatePath("/assets");
  return { ok: true as const, count: toEnqueue.length };
}