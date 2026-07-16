import "server-only";

import type { SupabaseClient } from "@supabase/supabase-js";

export const EVIDENCE_BUCKET = "scan-evidence";

type AdminClient = SupabaseClient;

let bucketEnsured = false;

export async function ensureEvidenceBucket(admin: AdminClient): Promise<void> {
  if (bucketEnsured) return;

  const { data: buckets, error } = await admin.storage.listBuckets();
  if (error) throw new Error(error.message);

  const exists = (buckets ?? []).some((bucket) => bucket.name === EVIDENCE_BUCKET);
  if (!exists) {
    const { error: createErr } = await admin.storage.createBucket(EVIDENCE_BUCKET, {
      public: false,
      fileSizeLimit: 6 * 1024 * 1024,
      allowedMimeTypes: ["image/png", "image/x-icon", "image/vnd.microsoft.icon"],
    });
    if (createErr) throw new Error(createErr.message);
  }

  bucketEnsured = true;
}

export async function uploadEvidenceBuffer(
  admin: AdminClient,
  path: string,
  body: Buffer,
  contentType: string,
): Promise<string> {
  await ensureEvidenceBucket(admin);
  const { error } = await admin.storage.from(EVIDENCE_BUCKET).upload(path, body, {
    contentType,
    upsert: true,
    cacheControl: "3600",
  });
  if (error) throw new Error(error.message);
  return path;
}

export async function downloadEvidenceBuffer(
  admin: AdminClient,
  path: string | null | undefined,
): Promise<Buffer | null> {
  if (!path) return null;
  await ensureEvidenceBucket(admin);
  const { data, error } = await admin.storage.from(EVIDENCE_BUCKET).download(path);
  if (error || !data) return null;
  return Buffer.from(await data.arrayBuffer());
}

export async function createEvidenceSignedUrl(
  admin: AdminClient,
  path: string | null | undefined,
  expiresIn = 3600,
): Promise<string | null> {
  if (!path) return null;
  await ensureEvidenceBucket(admin);
  const { data, error } = await admin.storage
    .from(EVIDENCE_BUCKET)
    .createSignedUrl(path, expiresIn);
  if (error) return null;
  return data.signedUrl;
}
