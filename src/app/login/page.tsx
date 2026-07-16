"use client";

import { Suspense, useActionState, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { signInAction, signUpAction, type AuthActionState } from "@/app/actions/auth";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";
import { BUILD_HASH } from "@/lib/build";
import { cn } from "@/lib/format";
import { SystemOverrideShader } from "@/components/ui/SystemOverrideShader";
import { TerminalLogs } from "@/components/ui/TerminalLogs";

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
    <div className="relative min-h-[100dvh] w-full overflow-hidden bg-void flex items-center justify-center bg-grid">

      {/* Background WebGL Shader */}
      <SystemOverrideShader />

      {/* Decorative Radar Sweep in background */}
      <div className="pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 mix-blend-screen opacity-30">
        <div className="h-[800px] w-[800px] rounded-full border border-live/20">
          <div className="absolute inset-0 rounded-full border border-live/10 scale-75" />
          <div className="absolute inset-0 rounded-full border border-live/5 scale-50" />
          <div className="radar-sweep absolute inset-0 origin-center">
            <div className="h-1/2 w-full bg-gradient-to-t from-live/20 to-transparent" />
          </div>
        </div>
      </div>

      {/* Left and Right Scrolling Terminal Logs */}
      <TerminalLogs side="left" className="hidden lg:block z-10" />
      <TerminalLogs side="right" className="hidden lg:block z-10" />

      {/* Top Left Header */}
      <div className="absolute top-6 left-6 z-20 flex items-center gap-2">
        <span className="animate-pulse font-data font-bold text-live">{"_>"}</span>
        <span className="font-data text-[12px] uppercase tracking-[0.2em] text-live/80">SYSTEM_OVERRIDE</span>
      </div>

      {/* Top Right Header */}
      <div className="absolute top-6 right-6 z-20 flex items-center gap-4 font-data text-[11px] uppercase tracking-wider text-critical/60">
        <span>NULL</span>
        <span>VOID</span>
        <span className="text-critical">OFFLINE</span>
      </div>

      {/* Main Content Area */}
      <div className="relative z-20 flex w-full flex-col items-center justify-center">

        {/* Giant Glitch Text */}
        <div className="mb-12 text-center select-none">
          <p className="mb-4 font-data text-[12px] uppercase tracking-[0.4em] text-text-faint">
            FICTIONAL SIMULATION // COSMETIC STATE ONLY
          </p>
          <h1
            className="glitch-3d type-display font-display font-bold uppercase tracking-tight text-live text-6xl sm:text-8xl lg:text-[140px]"
            data-text="DATUM"
          >
            DATUM
          </h1>
          <p className="mt-8 max-w-xl mx-auto font-data text-[13px] text-live/60 crt-flicker">
            This is a generic placeholder defacement copy. No system was accessed, no
            vulnerability was used, and no real person or organization is involved.
          </p>
        </div>

        {/* Authentication Panel */}
        <div className="w-full max-w-md px-6">
          <section className="relative flex items-center bg-carbon/80 backdrop-blur-md px-6 py-10 sm:px-12 border border-live/20 rounded-md shadow-[0_0_30px_rgba(184,240,76,0.1)]">
            <RegistrationMarks />
            {mode === "signin" ? (
              <SignInForm onSwitch={() => setMode("signup")} />
            ) : (
              <SignUpForm onSwitch={() => setMode("signin")} />
            )}

            <p className="absolute bottom-[-40px] left-0 font-data text-[11px] text-live/40">
              {">"} build {BUILD_HASH} · SECURE SESSION_
            </p>
          </section>
        </div>
      </div>
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
        <p className="type-label !text-live/60">Authenticate</p>
        <h2 className="mt-1 type-h2 text-live">Terminal Access</h2>
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

      <Input label="Email" name="email" type="email" autoComplete="email" required maxLength={254} disabled={pending} />
      <Input label="Password" name="password" type="password" autoComplete="current-password" required minLength={1} maxLength={128} disabled={pending} />

      <Button type="submit" className="w-full !border-live !text-live hover:!bg-live/10" variant="secondary" disabled={pending}>
        {pending ? "Authenticating…" : "Authenticate"}
      </Button>

      <p className="type-small text-text-dim text-center">
        No clearance?{" "}
        <button type="button" onClick={onSwitch} className="font-data text-[12px] text-live underline-offset-2 hover:underline">
          Request access
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
        <p className="type-label !text-live/60">Register</p>
        <h2 className="mt-1 type-h2 text-live">Request Access</h2>
      </div>

      {state.error ? <AuthBanner tone="critical">{state.error}</AuthBanner> : null}
      {state.message ? <AuthBanner tone="secure">{state.message}</AuthBanner> : null}

      <Input label="Email" name="email" type="email" autoComplete="email" required maxLength={254} disabled={pending} />
      <Input label="Password" name="password" type="password" autoComplete="new-password" required minLength={12} maxLength={128} disabled={pending} hint="At least 12 characters with upper, lower, number, and symbol." />
      <Input label="Confirm password" name="confirmPassword" type="password" autoComplete="new-password" required minLength={12} maxLength={128} disabled={pending} />

      <Button type="submit" className="w-full !border-live !text-live hover:!bg-live/10" variant="secondary" disabled={pending}>
        {pending ? "Creating account…" : "Submit request"}
      </Button>

      <p className="type-small text-text-dim text-center">
        Already registered?{" "}
        <button type="button" onClick={onSwitch} className="font-data text-[12px] text-live underline-offset-2 hover:underline">
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

function AuthBanner({ children, tone }: { children: string; tone: "critical" | "secure" }) {
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
