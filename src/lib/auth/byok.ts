import "server-only";

import { createAdminClient } from "@/lib/supabase/admin";
import { createServerSupabase } from "@/lib/supabase/server";
import { openSecret, sealSecret, isSealedSecret } from "@/lib/auth/secret-box";
import type { ByokKeyStatus } from "@/lib/auth/byok-shared";

export type { ByokKeyStatus };
export { KEY_MASK_SENTINEL } from "@/lib/auth/byok-shared";

export interface ByokSecrets {
  geminiApiKey: string | null;
  shodanApiKey: string | null;
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** Strip paste artifacts (quotes, zero-width chars) without logging the secret. */
export function sanitizeApiKey(raw: string): string {
  return raw
    .trim()
    .replace(/^["']+|["']+$/g, "")
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .trim();
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

function envFallbacks(): ByokSecrets {
  return {
    geminiApiKey: process.env.GEMINI_API_KEY?.trim() || null,
    shodanApiKey: process.env.SHODAN_API_KEY?.trim() || null,
  };
}

/**
 * Load BYOK secrets for one user via service role.
 * Caller must pass the authenticated / asset-owner user id — never a client-supplied id blindly.
 * Secrets are AES-GCM sealed at rest; never returned to the browser.
 */
export async function loadByokSecrets(userId: string): Promise<ByokSecrets> {
  if (!UUID_RE.test(userId)) {
    return { geminiApiKey: null, shodanApiKey: null };
  }
  if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
    return envFallbacks();
  }

  try {
    const admin = createAdminClient();
    const { data, error } = await admin
      .from("user_api_keys")
      .select("gemini_api_key, shodan_api_key")
      .eq("user_id", userId)
      .maybeSingle();

    if (error) {
      return envFallbacks();
    }

    let userGemini: string | null = null;
    let userShodan: string | null = null;
    const upgrades: { gemini_api_key?: string; shodan_api_key?: string } = {};
    try {
      const rawG = data?.gemini_api_key as string | null;
      const g = openSecret(rawG);
      userGemini = g ? sanitizeApiKey(g) : null;
      if (userGemini && rawG && !isSealedSecret(rawG)) {
        upgrades.gemini_api_key = sealSecret(userGemini);
      }
    } catch {
      userGemini = null;
    }
    try {
      const rawS = data?.shodan_api_key as string | null;
      const s = openSecret(rawS);
      userShodan = s ? sanitizeApiKey(s) : null;
      if (userShodan && rawS && !isSealedSecret(rawS)) {
        upgrades.shodan_api_key = sealSecret(userShodan);
      }
    } catch {
      userShodan = null;
    }

    if (Object.keys(upgrades).length > 0) {
      await admin.from("user_api_keys").update(upgrades).eq("user_id", userId);
    }

    const secrets: ByokSecrets = {
      geminiApiKey: userGemini || envFallbacks().geminiApiKey,
      shodanApiKey: userShodan || envFallbacks().shodanApiKey,
    };

    // #region agent log
    fetch("http://127.0.0.1:7781/ingest/1e3609e4-83e2-4af4-abe1-9c10d5bd2172", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "749116" },
      body: JSON.stringify({
        sessionId: "749116",
        runId: "byok-secure",
        hypothesisId: "H-load",
        location: "byok.ts:loadByokSecrets",
        message: "byok secrets loaded",
        data: {
          userIdPrefix: userId.slice(0, 8),
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
        },
        timestamp: Date.now(),
      }),
    }).catch(() => {});
    // #endregion

    return secrets;
  } catch {
    return envFallbacks();
  }
}

/** Persist one sealed key for the authenticated user (RPC). */
export async function persistMySealedKey(opts: {
  gemini?: string | null;
  shodan?: string | null;
  clearGemini?: boolean;
  clearShodan?: boolean;
}): Promise<{ ok: true; status: ByokKeyStatus } | { ok: false; error: string }> {
  let sealedGemini: string | null = null;
  let sealedShodan: string | null = null;

  try {
    if (opts.gemini) sealedGemini = sealSecret(opts.gemini);
    if (opts.shodan) sealedShodan = sealSecret(opts.shodan);
  } catch {
    return { ok: false, error: "Server encryption is not configured." };
  }

  const supabase = await createServerSupabase();
  const { data, error } = await supabase.rpc("set_my_api_keys", {
    p_gemini: sealedGemini,
    p_shodan: sealedShodan,
    p_clear_gemini: Boolean(opts.clearGemini),
    p_clear_shodan: Boolean(opts.clearShodan),
  });

  if (error) {
    return { ok: false, error: "Could not save API key. Ensure migrations are applied." };
  }

  const status = await getByokStatus();
  const row = (data ?? {}) as { geminiConfigured?: boolean; shodanConfigured?: boolean };
  return {
    ok: true,
    status: {
      geminiConfigured: Boolean(row.geminiConfigured ?? status.geminiConfigured),
      shodanConfigured: Boolean(row.shodanConfigured ?? status.shodanConfigured),
      geminiEnvConfigured: status.geminiEnvConfigured,
    },
  };
}
