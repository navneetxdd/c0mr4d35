import "server-only";

import { createHash } from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";

export interface AdhocBaselineRow {
  user_id: string;
  target_key: string;
  target_url: string;
  html_snapshot: string | null;
  signals: Record<string, unknown>;
  screenshot_path: string | null;
  favicon_hash: string | null;
}

export function normalizeTargetUrl(raw: string): string {
  const input = raw.includes("://") ? raw : `https://${raw}`;
  const url = new URL(input);
  url.hash = "";
  if ((url.protocol === "https:" && url.port === "443") || (url.protocol === "http:" && url.port === "80")) {
    url.port = "";
  }
  if (url.pathname === "") url.pathname = "/";
  if (url.pathname.length > 1 && url.pathname.endsWith("/")) {
    url.pathname = url.pathname.slice(0, -1);
  }
  url.search = "";
  url.hostname = url.hostname.toLowerCase().replace(/^www\./, "");
  return url.toString();
}

export function targetKeyFromUrl(raw: string): string {
  return createHash("sha256").update(normalizeTargetUrl(raw)).digest("hex");
}

export async function loadAdhocBaseline(
  admin: SupabaseClient,
  rawTarget: string,
  userId: string,
): Promise<AdhocBaselineRow | null> {
  const targetKey = targetKeyFromUrl(rawTarget);
  const { data } = await admin
    .from("adhoc_baselines")
    .select("user_id,target_key,target_url,html_snapshot,signals,screenshot_path,favicon_hash")
    .eq("user_id", userId)
    .eq("target_key", targetKey)
    .maybeSingle();
  return (data as AdhocBaselineRow | null) ?? null;
}

export async function saveAdhocBaseline(
  admin: SupabaseClient,
  rawTarget: string,
  userId: string,
  values: Omit<AdhocBaselineRow, "user_id" | "target_key" | "target_url">,
): Promise<AdhocBaselineRow> {
  const target_url = normalizeTargetUrl(rawTarget);
  const target_key = targetKeyFromUrl(rawTarget);
  const { data, error } = await admin
    .from("adhoc_baselines")
    .upsert(
      {
        user_id: userId,
        target_key,
        target_url,
        html_snapshot: values.html_snapshot,
        signals: values.signals,
        screenshot_path: values.screenshot_path,
        favicon_hash: values.favicon_hash,
      },
      { onConflict: "user_id,target_key" },
    )
    .select("user_id,target_key,target_url,html_snapshot,signals,screenshot_path,favicon_hash")
    .single();
  if (error || !data) throw new Error(error?.message ?? "Could not save ad-hoc baseline");
  return data as AdhocBaselineRow;
}
