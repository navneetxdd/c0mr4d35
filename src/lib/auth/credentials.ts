const EMAIL_RE =
  /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;

export function normalizeEmail(raw: string): string {
  return raw.trim().toLowerCase().slice(0, 254);
}

export function isValidEmail(email: string): boolean {
  return EMAIL_RE.test(email);
}

export function validatePassword(password: string): { ok: true } | { ok: false; error: string } {
  if (password.length < 12) {
    return { ok: false, error: "Password must be at least 12 characters" };
  }
  if (password.length > 128) {
    return { ok: false, error: "Password must be at most 128 characters" };
  }
  if (!/[a-z]/.test(password)) {
    return { ok: false, error: "Password must include a lowercase letter" };
  }
  if (!/[A-Z]/.test(password)) {
    return { ok: false, error: "Password must include an uppercase letter" };
  }
  if (!/[0-9]/.test(password)) {
    return { ok: false, error: "Password must include a number" };
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return { ok: false, error: "Password must include a symbol" };
  }
  if (/\s/.test(password)) {
    return { ok: false, error: "Password cannot contain spaces" };
  }
  return { ok: true };
}
