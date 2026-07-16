import "server-only";

import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

const PREFIX = "enc:v1:";

/**
 * Derive a 32-byte key from BYOK_ENCRYPTION_SECRET (preferred) or a
 * deploy-only fallback. Never use a public env var here.
 */
function encryptionKey(): Buffer {
  const secret =
    process.env.BYOK_ENCRYPTION_SECRET?.trim() ||
    process.env.SUPABASE_SERVICE_ROLE_KEY?.trim() ||
    "";
  if (!secret) {
    throw new Error("BYOK encryption secret is not configured");
  }
  return createHash("sha256").update(`datum-byok-v1:${secret}`).digest();
}

/** AES-256-GCM. Output: enc:v1:<iv>.<tag>.<ciphertext> (base64url). */
export function sealSecret(plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${PREFIX}${iv.toString("base64url")}.${tag.toString("base64url")}.${encrypted.toString("base64url")}`;
}

/** Decrypt sealed values; pass through legacy plaintext until next save. */
export function openSecret(stored: string | null | undefined): string | null {
  if (!stored) return null;
  const value = stored.trim();
  if (!value) return null;
  if (!value.startsWith(PREFIX)) return value;

  const payload = value.slice(PREFIX.length);
  const [ivB64, tagB64, dataB64] = payload.split(".");
  if (!ivB64 || !tagB64 || !dataB64) {
    throw new Error("Corrupt sealed secret");
  }
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey(), Buffer.from(ivB64, "base64url"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64url"));
  const plain = Buffer.concat([
    decipher.update(Buffer.from(dataB64, "base64url")),
    decipher.final(),
  ]);
  return plain.toString("utf8");
}

export function isSealedSecret(stored: string | null | undefined): boolean {
  return Boolean(stored?.startsWith(PREFIX));
}
