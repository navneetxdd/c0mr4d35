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

/** Strip paste artifacts (quotes, zero-width chars) without logging the secret. */
export function sanitizeApiKey(raw: string): string {
  return raw
    .trim()
    .replace(/^["']+|["']+$/g, "")
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .trim();
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
    const { data, error } = await admin
      .from("user_api_keys")
      .select("gemini_api_key, shodan_api_key")
      .eq("user_id", userId)
      .maybeSingle();

    const userGemini =
      typeof data?.gemini_api_key === "string" && data.gemini_api_key.trim()
        ? sanitizeApiKey(data.gemini_api_key)
        : null;
    const userShodan =
      typeof data?.shodan_api_key === "string" && data.shodan_api_key.trim()
        ? sanitizeApiKey(data.shodan_api_key)
        : null;

    const secrets = {
      geminiApiKey: userGemini || process.env.GEMINI_API_KEY?.trim() || null,
      shodanApiKey: userShodan || process.env.SHODAN_API_KEY?.trim() || null,
    };

    // #region agent log
    fetch("http://127.0.0.1:7781/ingest/1e3609e4-83e2-4af4-abe1-9c10d5bd2172", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "749116" },
      body: JSON.stringify({
        sessionId: "749116",
        runId: "byok-fix",
        hypothesisId: "H-load",
        location: "byok.ts:loadByokSecrets",
        message: "byok secrets loaded",
        data: {
          hasDbError: Boolean(error),
          hasUserGemini: Boolean(userGemini),
          hasUserShodan: Boolean(userShodan),
          geminiKind: secrets.geminiApiKey?.startsWith("AQ.")
            ? "AQ"
            : secrets.geminiApiKey?.startsWith("AIza")
              ? "AIza"
              : secrets.geminiApiKey
                ? "other"
                : "none",
          geminiLen: secrets.geminiApiKey?.length ?? 0,
          shodanLen: secrets.shodanApiKey?.length ?? 0,
          sourceGemini: userGemini ? "user" : secrets.geminiApiKey ? "env" : "none",
          sourceShodan: userShodan ? "user" : secrets.shodanApiKey ? "env" : "none",
        },
        timestamp: Date.now(),
      }),
    }).catch(() => {});
    // #endregion

    return secrets;
  } catch {
    return {
      geminiApiKey: process.env.GEMINI_API_KEY?.trim() || null,
      shodanApiKey: process.env.SHODAN_API_KEY?.trim() || null,
    };
  }
}
