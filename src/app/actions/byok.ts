"use server";

import { revalidatePath } from "next/cache";
import { requireUser } from "@/lib/auth/require";
import {
  getByokStatus,
  persistMySealedKey,
  sanitizeApiKey,
  type ByokKeyStatus,
} from "@/lib/auth/byok";
import { KEY_MASK_SENTINEL } from "@/lib/auth/byok-shared";

export type ByokActionState = {
  ok: boolean;
  error: string | null;
  message: string | null;
  status: ByokKeyStatus | null;
};

const empty: ByokActionState = {
  ok: false,
  error: null,
  message: null,
  status: null,
};

function isMaskOrEmpty(raw: string): boolean {
  const v = raw.trim();
  return !v || v === KEY_MASK_SENTINEL;
}

export async function saveGeminiKeyAction(
  _prev: ByokActionState,
  formData: FormData,
): Promise<ByokActionState> {
  try {
    await requireUser();
  } catch {
    return { ...empty, error: "Authentication required" };
  }

  const clear = formData.get("clearGemini") === "on";
  const raw = String(formData.get("geminiApiKey") ?? "");
  const gemini = sanitizeApiKey(raw);

  if (!clear && isMaskOrEmpty(raw)) {
    const status = await getByokStatus();
    return {
      ok: true,
      error: null,
      message: status.geminiConfigured ? "Gemini key unchanged." : "Paste a Gemini key to save.",
      status,
    };
  }

  if (!clear && (gemini.length < 20 || gemini.length > 200)) {
    return { ...empty, error: "Gemini key length looks invalid.", status: await getByokStatus() };
  }

  const result = await persistMySealedKey({
    gemini: clear ? null : gemini,
    clearGemini: clear,
  });

  revalidatePath("/settings");
  if (!result.ok) {
    return { ...empty, error: result.error, status: await getByokStatus() };
  }
  return {
    ok: true,
    error: null,
    message: clear ? "Gemini key cleared." : "Gemini key saved for your account only.",
    status: result.status,
  };
}

export async function saveShodanKeyAction(
  _prev: ByokActionState,
  formData: FormData,
): Promise<ByokActionState> {
  try {
    await requireUser();
  } catch {
    return { ...empty, error: "Authentication required" };
  }

  const clear = formData.get("clearShodan") === "on";
  const raw = String(formData.get("shodanApiKey") ?? "");
  const shodan = sanitizeApiKey(raw);

  if (!clear && isMaskOrEmpty(raw)) {
    const status = await getByokStatus();
    return {
      ok: true,
      error: null,
      message: status.shodanConfigured ? "Shodan key unchanged." : "Paste a Shodan key to save.",
      status,
    };
  }

  if (!clear && (shodan.length < 16 || shodan.length > 200)) {
    return { ...empty, error: "Shodan key length looks invalid.", status: await getByokStatus() };
  }

  // Soft-validate against Shodan api-info (does not require Membership).
  if (!clear) {
    try {
      const infoRes = await fetch(
        `https://api.shodan.io/api-info?key=${encodeURIComponent(shodan)}`,
        { signal: AbortSignal.timeout(8_000), headers: { accept: "application/json" } },
      );
      if (infoRes.status === 401) {
        return {
          ...empty,
          error: "Shodan rejected this API key (invalid).",
          status: await getByokStatus(),
        };
      }
    } catch {
      // Network blip — still allow save; scan path will report honestly.
    }
  }

  const result = await persistMySealedKey({
    shodan: clear ? null : shodan,
    clearShodan: clear,
  });

  revalidatePath("/settings");
  if (!result.ok) {
    return { ...empty, error: result.error, status: await getByokStatus() };
  }
  return {
    ok: true,
    error: null,
    message: clear
      ? "Shodan key cleared."
      : "Shodan key saved for your account only. Host/DNS APIs need Membership; InternetDB works without it.",
    status: result.status,
  };
}
