/**
 * Reject open redirects. Only same-origin relative paths are allowed.
 */
export function safeRedirectPath(next: string | null | undefined): string {
  if (!next) return "/";

  const trimmed = next.trim();
  if (!trimmed.startsWith("/") || trimmed.startsWith("//")) return "/";
  if (trimmed.includes("\\") || trimmed.includes("@") || trimmed.includes(":")) return "/";

  let decoded = trimmed;
  try {
    decoded = decodeURIComponent(trimmed);
  } catch {
    return "/";
  }

  if (
    decoded.startsWith("//") ||
    decoded.includes("://") ||
    decoded.includes("\\") ||
    decoded.includes("@")
  ) {
    return "/";
  }

  return trimmed;
}
