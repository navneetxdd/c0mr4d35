"use server";

import { revalidatePath } from "next/cache";
import { createServerSupabase } from "@/lib/supabase/server";
import { requireUser } from "@/lib/auth/require";
import { getByokStatus, sanitizeApiKey, type ByokKeyStatus } from "@/lib/auth/byok";

export type ByokActionState = {
  ok: boolean;
  error: string | null;
  message: string | null;
  status: ByokKeyStatus | null;
};

export async function saveByokKeysAction(
  _prev: ByokActionState,
  formData: FormData,
): Promise<ByokActionState> {
  try {
    await requireUser();
  } catch {
    return { ok: false, error: "Authentication required", message: null, status: null };
  }

  const gemini = sanitizeApiKey(String(formData.get("geminiApiKey") ?? ""));
  const shodan = sanitizeApiKey(String(formData.get("shodanApiKey") ?? ""));
  const clearGemini = formData.get("clearGemini") === "on";
  const clearShodan = formData.get("clearShodan") === "on";

  if (gemini && gemini.length > 200) {
    return { ok: false, error: "Gemini key is too long", message: null, status: null };
  }
  if (shodan && shodan.length > 200) {
    return { ok: false, error: "Shodan key is too long", message: null, status: null };
  }

  const supabase = await createServerSupabase();
  const { data, error } = await supabase.rpc("set_my_api_keys", {
    p_gemini: gemini || null,
    p_shodan: shodan || null,
    p_clear_gemini: clearGemini,
    p_clear_shodan: clearShodan,
  });

  if (error) {
    return {
      ok: false,
      error: "Could not save API keys. Ensure migrations are applied.",
      message: null,
      status: null,
    };
  }

  revalidatePath("/settings");
  const status = await getByokStatus();
  const row = (data ?? {}) as { geminiConfigured?: boolean; shodanConfigured?: boolean };
  return {
    ok: true,
    error: null,
    message: "API keys updated.",
    status: {
      geminiConfigured: Boolean(row.geminiConfigured ?? status.geminiConfigured),
      shodanConfigured: Boolean(row.shodanConfigured ?? status.shodanConfigured),
      geminiEnvConfigured: status.geminiEnvConfigured,
    },
  };
}
