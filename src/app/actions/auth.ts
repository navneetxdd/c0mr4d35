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
const SIGNUP_MESSAGE =
  "If this email can be used, check your inbox to confirm your account before signing in.";

function emptyState(): AuthActionState {
  return { ok: false, signedIn: false, next: "/", error: null, message: null };
}

async function requestOrigin(): Promise<string> {
  const h = await headers();
  const host = h.get("x-forwarded-host") ?? h.get("host");
  if (!host) return "http://localhost:3000";
  const proto = h.get("x-forwarded-proto") ?? (host.includes("localhost") ? "http" : "https");
  return `${proto}://${host}`;
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

  // Anti-enumeration: never reveal whether the email already exists.
  if (error) {
    return { ok: true, signedIn: false, next: "/", error: null, message: SIGNUP_MESSAGE };
  }

  if (data.session) {
    return { ok: true, signedIn: true, next: "/", error: null, message: null };
  }

  return { ok: true, signedIn: false, next: "/", error: null, message: SIGNUP_MESSAGE };
}
