"use client";

import { Suspense, useActionState, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { signInAction, signUpAction, type AuthActionState } from "@/app/actions/auth";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";
import { BUILD_HASH } from "@/lib/build";
import { cn } from "@/lib/format";

const INITIAL: AuthActionState = {
  ok: false,
  signedIn: false,
  next: "/",
  error: null,
  message: null,
};

export default function LoginPage() {
  return (
    <Suspense>
      <AuthPage />
    </Suspense>
  );
}

function AuthPage() {
  const [mode, setMode] = useState<"signin" | "signup">("signin");

  return (
    <div className="grid min-h-[100dvh] lg:grid-cols-[2fr_3fr]">
      <section className="relative hidden overflow-hidden bg-void lg:flex flex-col justify-between p-10">
        <div>
          <p className="font-data text-[13px] tracking-[0.2em] text-live">DATUM</p>
          <p className="mt-6 max-w-sm type-h2 text-text">
            Establish the truth of a web asset, then watch for the moment it stops being
            true.
          </p>
        </div>
        <div className="relative h-32">
          <div className="absolute inset-x-0 top-1/2 h-px bg-text-faint/50" />
          <div className="baseline-drift absolute left-1/4 top-1/2 h-2 w-2 -translate-y-1/2 rounded-full bg-critical/80" />
          <div
            className="baseline-drift absolute left-1/2 top-1/2 h-1.5 w-1.5 -translate-y-1/2 rounded-full bg-watch/70"
            style={{ animationDelay: "1.2s" }}
          />
          <p className="absolute bottom-0 font-data text-[11px] text-text-faint">
            BASELINE · DRIFT BLIPS
          </p>
        </div>
        <p className="font-data text-[11px] text-text-faint">
          build {BUILD_HASH} · SECURE SESSION
        </p>
      </section>

      <section className="relative flex items-center bg-carbon px-6 py-12 sm:px-12">
        <RegistrationMarks />
        {mode === "signin" ? (
          <SignInForm onSwitch={() => setMode("signup")} />
        ) : (
          <SignUpForm onSwitch={() => setMode("signin")} />
        )}
      </section>
    </div>
  );
}

function SignInForm({ onSwitch }: { onSwitch: () => void }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [state, formAction, pending] = useActionState(signInAction, INITIAL);
  const configError = searchParams.get("error") === "config";
  const authError = searchParams.get("error") === "auth";

  useEffect(() => {
    if (state.signedIn) {
      router.replace(state.next);
      router.refresh();
    }
  }, [state.signedIn, state.next, router]);

  return (
    <form className="relative w-full max-w-md space-y-5" action={formAction}>
      <input type="hidden" name="next" value={searchParams.get("next") ?? "/"} />
      <Honeypot />

      <div>
        <p className="type-label">Authenticate</p>
        <h1 className="mt-2 type-h1 text-text">Sign in</h1>
        <p className="mt-2 type-small text-text-dim lg:hidden">
          Establish the truth. Measure the drift.
        </p>
      </div>

      {configError ? (
        <AuthBanner tone="critical">
          Authentication is unavailable — server configuration is incomplete.
        </AuthBanner>
      ) : null}
      {authError ? (
        <AuthBanner tone="critical">Sign-in link expired or invalid. Try again.</AuthBanner>
      ) : null}
      {state.error ? <AuthBanner tone="critical">{state.error}</AuthBanner> : null}
      {state.message ? <AuthBanner tone="secure">{state.message}</AuthBanner> : null}

      <Input
        label="Email"
        name="email"
        type="email"
        autoComplete="email"
        required
        maxLength={254}
        disabled={pending}
      />
      <Input
        label="Password"
        name="password"
        type="password"
        autoComplete="current-password"
        required
        minLength={1}
        maxLength={128}
        disabled={pending}
      />

      <Button type="submit" className="w-full" disabled={pending}>
        {pending ? "Authenticating…" : "Authenticate"}
      </Button>

      <p className="type-small text-text-dim">
        No account?{" "}
        <button
          type="button"
          onClick={onSwitch}
          className="font-data text-[12px] text-scan underline-offset-2 hover:underline"
        >
          Create one
        </button>
      </p>
    </form>
  );
}

function SignUpForm({ onSwitch }: { onSwitch: () => void }) {
  const router = useRouter();
  const [state, formAction, pending] = useActionState(signUpAction, INITIAL);

  useEffect(() => {
    if (state.signedIn) {
      router.replace(state.next);
      router.refresh();
    }
  }, [state.signedIn, state.next, router]);

  return (
    <form className="relative w-full max-w-md space-y-5" action={formAction}>
      <Honeypot />

      <div>
        <p className="type-label">Register</p>
        <h1 className="mt-2 type-h1 text-text">Create account</h1>
        <p className="mt-2 type-small text-text-dim">
          New accounts start as viewer. An admin can promote access later.
        </p>
      </div>

      {state.error ? <AuthBanner tone="critical">{state.error}</AuthBanner> : null}
      {state.message ? <AuthBanner tone="secure">{state.message}</AuthBanner> : null}

      <Input
        label="Email"
        name="email"
        type="email"
        autoComplete="email"
        required
        maxLength={254}
        disabled={pending}
      />
      <Input
        label="Password"
        name="password"
        type="password"
        autoComplete="new-password"
        required
        minLength={12}
        maxLength={128}
        disabled={pending}
        hint="At least 12 characters with upper, lower, number, and symbol."
      />
      <Input
        label="Confirm password"
        name="confirmPassword"
        type="password"
        autoComplete="new-password"
        required
        minLength={12}
        maxLength={128}
        disabled={pending}
      />

      <Button type="submit" className="w-full" disabled={pending}>
        {pending ? "Creating account…" : "Create account"}
      </Button>

      <p className="type-small text-text-dim">
        Already registered?{" "}
        <button
          type="button"
          onClick={onSwitch}
          className="font-data text-[12px] text-scan underline-offset-2 hover:underline"
        >
          Sign in
        </button>
      </p>
    </form>
  );
}

function Honeypot() {
  return (
    <div className="absolute -left-[9999px] h-0 w-0 overflow-hidden" aria-hidden="true">
      <label htmlFor="company">Company</label>
      <input id="company" name="company" type="text" tabIndex={-1} autoComplete="off" />
    </div>
  );
}

function AuthBanner({
  children,
  tone,
}: {
  children: string;
  tone: "critical" | "secure";
}) {
  return (
    <p
      className={cn(
        "rounded-sm border px-3 py-2 font-data text-[12px]",
        tone === "critical"
          ? "border-critical/40 bg-critical/10 text-critical"
          : "border-secure/40 bg-secure/10 text-secure",
      )}
      role="alert"
    >
      {children}
    </p>
  );
}
