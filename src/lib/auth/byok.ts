import "server-only";

import { createAdminClient } from "@/lib/supabase/admin";
import { createServerSupabase } from "@/lib/supabase/server";

export interface ByokKeyStatus {
  geminiConfigured: boolean;
  shodanConfigured: boolean;
  /** Env fallback for Gemini (deploy-level key). */
  geminiEnvConfigured: boolean;
}

export interface ByokSecrets {
  geminiApiKey: string | null;
  shodanApiKey: string | null;
}

export async function getByokStatus(): Promise<ByokKeyStatus> {
  const supabase = await createServerSupabase();
  const { data, error } = await supabase.rpc("get_my_api_key_status");
  if (error || !data || typeof data !== "object") {
    return {
      geminiConfigured: false,
      shodanConfigured: false,
      geminiEnvConfigured: Boolean(process.env.GEMINI_API_KEY?.trim()),
    };
  }
  const row = data as { geminiConfigured?: boolean; shodanConfigured?: boolean };
  return {
    geminiConfigured: Boolean(row.geminiConfigured),
    shodanConfigured: Boolean(row.shodanConfigured),
    geminiEnvConfigured: Boolean(process.env.GEMINI_API_KEY?.trim()),
  };
}

/** Load decrypted BYOK secrets for a user via service role (never expose to client). */
export async function loadByokSecrets(userId: string): Promise<ByokSecrets> {
  if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
    return {
      geminiApiKey: process.env.GEMINI_API_KEY?.trim() || null,
      shodanApiKey: process.env.SHODAN_API_KEY?.trim() || null,
    };
  }
  try {
    const admin = createAdminClient();
    const { data } = await admin
      .from("user_api_keys")
      .select("gemini_api_key, shodan_api_key")
      .eq("user_id", userId)
      .maybeSingle();

    const userGemini =
      typeof data?.gemini_api_key === "string" && data.gemini_api_key.trim()
        ? data.gemini_api_key.trim()
        : null;
    const userShodan =
      typeof data?.shodan_api_key === "string" && data.shodan_api_key.trim()
        ? data.shodan_api_key.trim()
        : null;

    return {
      geminiApiKey: userGemini || process.env.GEMINI_API_KEY?.trim() || null,
      shodanApiKey: userShodan || process.env.SHODAN_API_KEY?.trim() || null,
    };
  } catch {
    return {
      geminiApiKey: process.env.GEMINI_API_KEY?.trim() || null,
      shodanApiKey: process.env.SHODAN_API_KEY?.trim() || null,
    };
  }
}
