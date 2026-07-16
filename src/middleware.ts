import { NextResponse, type NextRequest } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { safeRedirectPath } from "@/lib/auth/safe-redirect";

/**
 * Refreshes the Supabase session on every request and gates the console behind
 * authentication. Public paths: the login page and the cron endpoint (which
 * authenticates with CRON_SECRET, not a session). Everything else requires a
 * signed-in user.
 *
 * NOTE: middleware is a convenience gate, not the security boundary. Row Level
 * Security + server-side requireRole() are the real enforcement — recent
 * middleware-bypass CVEs are exactly why auth is also checked at the data layer.
 */
const PUBLIC_PATHS = ["/login", "/auth"];

function isPublic(pathname: string): boolean {
  if (PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(p + "/"))) return true;
  if (pathname.startsWith("/api/cron")) return true; // secured by CRON_SECRET
  return false;
}

export async function middleware(request: NextRequest) {
  let response = NextResponse.next({ request });

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const { pathname } = request.nextUrl;

  if (!url || !anon) {
    if (process.env.NODE_ENV === "production" && !isPublic(pathname)) {
      const redirect = request.nextUrl.clone();
      redirect.pathname = "/login";
      redirect.searchParams.set("error", "config");
      return NextResponse.redirect(redirect);
    }
    return response;
  }

  const supabase = createServerClient(url, anon, {
    cookies: {
      getAll() {
        return request.cookies.getAll();
      },
      setAll(cookiesToSet) {
        for (const { name, value } of cookiesToSet) request.cookies.set(name, value);
        response = NextResponse.next({ request });
        for (const { name, value, options } of cookiesToSet) response.cookies.set(name, value, options);
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
    return NextResponse.redirect(redirect);
  }

  if (user && pathname === "/login") {
    const redirect = request.nextUrl.clone();
    redirect.pathname = safeRedirectPath(request.nextUrl.searchParams.get("next"));
    redirect.search = "";
    return NextResponse.redirect(redirect);
  }

  return response;
}

export const config = {
  // Run on everything except Next internals and static files.
  matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)"],
};
