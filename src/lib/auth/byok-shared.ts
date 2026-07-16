/** Shared BYOK constants safe for client + server (no secrets). */

export const KEY_MASK_SENTINEL = "••••••••••••••••";

export interface ByokKeyStatus {
  geminiConfigured: boolean;
  shodanConfigured: boolean;
  /** Env fallback for Gemini (deploy-level key). */
  geminiEnvConfigured: boolean;
}
