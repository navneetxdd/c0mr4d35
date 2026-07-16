import { NextResponse } from "next/server";
import type { EmailOtpType } from "@supabase/supabase-js";
import { safeRedirectPath } from "@/lib/auth/safe-redirect";
import { createServerSupabase } from "@/lib/supabase/server";

const APP_ORIGIN =
  process.env.NEXT_PUBLIC_APP_URL?.trim().replace(/\/$/, "") ||
  (process.env.VERCEL_PROJECT_PRODUCTION_URL
    ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL.replace(/\/$/, "")}`
    : null);

function publicOrigin(requestUrl: string): string {
  if (APP_ORIGIN) return APP_ORIGIN;
  return new URL(requestUrl).origin;
}

/**
 * Handles both Supabase email confirmation shapes:
 * 1) PKCE — after /auth/v1/verify, redirect lands with ?code=
 * 2) Token hash — custom templates link with ?token_hash=&type=
 *
 * Landing with neither used to silently redirect home without a session.
 */
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const code = searchParams.get("code");
  const tokenHash = searchParams.get("token_hash");
  const type = searchParams.get("type") as EmailOtpType | null;
  const next = safeRedirectPath(searchParams.get("next"));
  const origin = publicOrigin(request.url);
  const supabase = await createServerSupabase();

  if (code) {
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (error) {
      return NextResponse.redirect(`${origin}/login?error=auth`);
    }
    return NextResponse.redirect(`${origin}${next}`);
  }

  if (tokenHash && type) {
    const { error } = await supabase.auth.verifyOtp({ type, token_hash: tokenHash });
    if (error) {
      return NextResponse.redirect(`${origin}/login?error=auth`);
    }
    return NextResponse.redirect(`${origin}${next}`);
  }

  return NextResponse.redirect(`${origin}/login?error=auth`);
}
