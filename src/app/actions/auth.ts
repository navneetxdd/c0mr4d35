"use server";

import { headers } from "next/headers";
import { createServerSupabase } from "@/lib/supabase/server";
import { checkRateLimit } from "@/lib/auth/rate-limit";
import { getClientIp } from "@/lib/auth/client-ip";
import { isValidEmail, normalizeEmail, validatePassword } from "@/lib/auth/credentials";
import { safeRedirectPath } from "@/lib/auth/safe-redirect";

export type AuthActionState = {
  ok: boolean;
  signedIn: boolean;
  next: string;
  error: string | null;
  message: string | null;
};

const GENERIC_SIGNIN_ERROR = "Invalid email or password";
const RATE_LIMIT_ERROR = "Too many attempts. Try again later.";
const EMAIL_NOT_CONFIRMED_ERROR =
  "Confirm your email before signing in. Check your inbox for the verification link.";
const SIGNUP_MESSAGE =
  "If this email can be used, check your inbox to confirm your account before signing in.";
const SIGNUP_UNAVAILABLE_ERROR =
  "Registration is temporarily unavailable. Please try again in a few minutes.";

/**
 * True when a Supabase auth error is a system/delivery failure (rate limit,
 * email provider outage, upstream 5xx) rather than something tied to the
 * submitted credentials. These are NOT enumeration oracles — they don't reveal
 * whether the email already exists — so it's safe to surface them honestly
 * instead of falsely telling the user to check their inbox.
 */
function isSystemAuthError(status: number | undefined, code: string | undefined): boolean {
  const s = status ?? 0;
  const c = (code ?? "").toLowerCase();
  return (
    s === 429 ||
    s >= 500 ||
    c.includes("rate_limit") ||
    c.includes("email_send") ||
    c === "over_email_send_rate_limit" ||
    c === "email_provider_disabled" ||
    c === "smtp_send_failed"
  );
}

function emptyState(): AuthActionState {
  return { ok: false, signedIn: false, next: "/", error: null, message: null };
}

async function requestOrigin(): Promise<string> {
  // Prefer explicit public app URL so auth emails never point at a spoofed Host.
  const configured =
    process.env.NEXT_PUBLIC_APP_URL?.trim() ||
    process.env.APP_URL?.trim() ||
    "";
  if (configured) {
    return configured.replace(/\/$/, "");
  }

  if (process.env.VERCEL_PROJECT_PRODUCTION_URL) {
    return `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL.replace(/\/$/, "")}`;
  }
  if (process.env.VERCEL_URL) {
    return `https://${process.env.VERCEL_URL.replace(/\/$/, "")}`;
  }

  // Local development only — never mint email redirects from raw Host headers
  // on any hosted environment (Host-header injection → account takeover).
  if (process.env.NODE_ENV === "development" && !process.env.VERCEL) {
    const h = await headers();
    const host = h.get("host");
    if (host && (host.startsWith("localhost:") || host === "localhost" || host.startsWith("127.0.0.1"))) {
      return `http://${host}`;
    }
  }

  throw new Error("Auth redirect origin misconfigured — set NEXT_PUBLIC_APP_URL");
}

async function enforceAuthRateLimit(ip: string, email: string): Promise<boolean> {
  const [ipOk, emailOk, burstOk] = await Promise.all([
    checkRateLimit(`auth:ip:${ip}`, 30, 900),
    checkRateLimit(`auth:email:${email}`, 8, 900),
    checkRateLimit(`auth:burst:${ip}`, 6, 60),
  ]);
  return ipOk && emailOk && burstOk;
}

export async function signInAction(
  _prev: AuthActionState,
  formData: FormData,
): Promise<AuthActionState> {
  const honeypot = String(formData.get("company") ?? "").trim();
  if (honeypot) {
    await new Promise((resolve) => setTimeout(resolve, 800));
    return { ...emptyState(), error: GENERIC_SIGNIN_ERROR };
  }

  const email = normalizeEmail(String(formData.get("email") ?? ""));
  const password = String(formData.get("password") ?? "");
  const next = safeRedirectPath(String(formData.get("next") ?? "/"));
  const ip = await getClientIp();

  if (!isValidEmail(email) || password.length < 1 || password.length > 128) {
    return { ...emptyState(), error: GENERIC_SIGNIN_ERROR, next };
  }

  if (!(await enforceAuthRateLimit(ip, email))) {
    return { ...emptyState(), error: RATE_LIMIT_ERROR, next };
  }

  const supabase = await createServerSupabase();
  const { error } = await supabase.auth.signInWithPassword({ email, password });

  if (error) {
    // Supabase only returns this when the password is correct but the email
    // is still unconfirmed — safe to surface without opening an enumeration oracle.
    const code = (error.code ?? "").toLowerCase();
    if (code === "email_not_confirmed") {
      return { ...emptyState(), error: EMAIL_NOT_CONFIRMED_ERROR, next };
    }
    return { ...emptyState(), error: GENERIC_SIGNIN_ERROR, next };
  }

  return { ok: true, signedIn: true, next, error: null, message: null };
}

export async function signUpAction(
  _prev: AuthActionState,
  formData: FormData,
): Promise<AuthActionState> {
  const honeypot = String(formData.get("company") ?? "").trim();
  if (honeypot) {
    await new Promise((resolve) => setTimeout(resolve, 800));
    return { ...emptyState(), message: SIGNUP_MESSAGE };
  }

  const email = normalizeEmail(String(formData.get("email") ?? ""));
  const password = String(formData.get("password") ?? "");
  const confirm = String(formData.get("confirmPassword") ?? "");
  const ip = await getClientIp();

  if (!isValidEmail(email)) {
    return { ...emptyState(), error: "Enter a valid email address" };
  }

  const passwordCheck = validatePassword(password);
  if (!passwordCheck.ok) {
    return { ...emptyState(), error: passwordCheck.error };
  }

  if (password !== confirm) {
    return { ...emptyState(), error: "Passwords do not match" };
  }

  if (!(await enforceAuthRateLimit(ip, email))) {
    return { ...emptyState(), error: RATE_LIMIT_ERROR };
  }

  const supabase = await createServerSupabase();
  const origin = await requestOrigin();
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      emailRedirectTo: `${origin}/auth/callback?next=${encodeURIComponent("/")}`,
    },
  });

  if (error) {
    // Delivery/system failures (e.g. email rate limit exhausted) must not be
    // masked as "check your inbox" — no email was sent and no account created.
    // Surfacing these is safe: they're independent of whether the email exists.
    if (isSystemAuthError(error.status, error.code)) {
      return { ...emptyState(), error: SIGNUP_UNAVAILABLE_ERROR };
    }
    // Anti-enumeration: for credential-tied errors, never reveal whether the
    // email already exists.
    return { ok: true, signedIn: false, next: "/", error: null, message: SIGNUP_MESSAGE };
  }

  if (data.session) {
    return { ok: true, signedIn: true, next: "/", error: null, message: null };
  }

  return { ok: true, signedIn: false, next: "/", error: null, message: SIGNUP_MESSAGE };
}
