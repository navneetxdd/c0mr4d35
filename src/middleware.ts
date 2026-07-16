import { NextResponse, type NextRequest } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { safeRedirectPath } from "@/lib/auth/safe-redirect";
import { getSupabaseAnonEnv } from "@/lib/supabase/env";
import { buildCspHeader } from "@/lib/security/csp";

/**
 * Refreshes the Supabase session on every request and gates the console behind
 * authentication. Public paths: the login page and the cron endpoint (which
 * authenticates with CRON_SECRET, not a session). Everything else requires a
 * signed-in user.
 *
 * NOTE: middleware is a convenience gate, not the security boundary. Row Level
 * Security + server-side requireRole() are the real enforcement — recent
 * middleware-bypass CVEs are exactly why auth is also checked at the data layer.
 *
 * Also mints a per-request CSP nonce (script-src) so production does not need
 * 'unsafe-inline' for scripts.
 */
const PUBLIC_PATHS = ["/login", "/auth"];

function isPublic(pathname: string): boolean {
  if (PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(p + "/"))) return true;
  if (pathname.startsWith("/api/cron")) return true; // secured by CRON_SECRET
  return false;
}

/** This app is same-origin only — never advertise open CORS. */
function stripOpenCors(response: NextResponse): NextResponse {
  response.headers.delete("Access-Control-Allow-Origin");
  response.headers.delete("Access-Control-Allow-Credentials");
  response.headers.delete("Access-Control-Allow-Methods");
  response.headers.delete("Access-Control-Allow-Headers");
  return response;
}

function applyCsp(response: NextResponse, csp: string): NextResponse {
  response.headers.set("Content-Security-Policy", csp);
  return stripOpenCors(response);
}

function createNonce(): string {
  return Buffer.from(crypto.randomUUID()).toString("base64");
}

export async function middleware(request: NextRequest) {
  const nonce = createNonce();
  const isDev = process.env.NODE_ENV === "development";
  const csp = buildCspHeader(nonce, isDev);

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  // Next.js reads this request CSP to stamp nonces on its scripts.
  requestHeaders.set("Content-Security-Policy", csp);

  let response = applyCsp(
    NextResponse.next({ request: { headers: requestHeaders } }),
    csp,
  );

  const { url, anonKey } = getSupabaseAnonEnv();
  const { pathname } = request.nextUrl;

  if (!url || !anonKey) {
    if (isPublic(pathname)) return response;
    const redirect = request.nextUrl.clone();
    redirect.pathname = "/login";
    redirect.searchParams.set("error", "config");
    return applyCsp(NextResponse.redirect(redirect), csp);
  }

  const supabase = createServerClient(url, anonKey, {
    cookies: {
      getAll() {
        return request.cookies.getAll();
      },
      setAll(cookiesToSet) {
        for (const { name, value } of cookiesToSet) request.cookies.set(name, value);
        response = applyCsp(
          NextResponse.next({ request: { headers: requestHeaders } }),
          csp,
        );
        for (const { name, value, options } of cookiesToSet) {
          response.cookies.set(name, value, options);
        }
      },
    },
  });

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user && !isPublic(pathname)) {
    const redirect = request.nextUrl.clone();
    redirect.pathname = "/login";
    redirect.searchParams.set("next", safeRedirectPath(pathname));
    return applyCsp(NextResponse.redirect(redirect), csp);
  }

  if (user && pathname === "/login") {
    const redirect = request.nextUrl.clone();
    redirect.pathname = safeRedirectPath(request.nextUrl.searchParams.get("next"));
    redirect.search = "";
    return applyCsp(NextResponse.redirect(redirect), csp);
  }

  return response;
}

export const config = {
  // Run on everything except Next internals and static files.
  matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)"],
};
