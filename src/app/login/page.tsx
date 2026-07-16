"use client";

import dynamic from "next/dynamic";
import { Suspense, useActionState, useEffect, useState, type ReactNode } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { signInAction, signUpAction, type AuthActionState } from "@/app/actions/auth";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";
import { BUILD_HASH } from "@/lib/build";
import { cn } from "@/lib/format";
import { TerminalLogs } from "@/components/ui/TerminalLogs";

const SystemOverrideShader = dynamic(
  () => import("@/components/ui/SystemOverrideShader").then((m) => m.SystemOverrideShader),
  { ssr: false },
);

/** Public production URL — local clones intentionally lack private server secrets. */
const HOSTED_APP_URL =
  process.env.NEXT_PUBLIC_HOSTED_APP_URL?.trim() || "https://systemsiege.vercel.app";

const INITIAL: AuthActionState = {
  ok: false,
  signedIn: false,
  next: "/",
  error: null,
  message: null,
};

function isLocalHost(): boolean {
  if (typeof window === "undefined") return false;
  const host = window.location.hostname;
  return host === "localhost" || host === "127.0.0.1" || host === "[::1]";
}

export default function LoginPage() {
  return (
    <Suspense>
      <AuthPage />
    </Suspense>
  );
}

function AuthPage() {
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  // Password managers inject styles/buttons into email/password fields before
  // React hydrates, which mismatches SSR HTML. Render the form only after mount.
  const [formReady, setFormReady] = useState(false);

  useEffect(() => {
    setFormReady(true);
  }, []);

  return (
    <div className="relative min-h-[100dvh] w-full overflow-hidden bg-void bg-grid">
      <SystemOverrideShader />

      <TerminalLogs side="left" className="z-[5] hidden xl:block" />
      <TerminalLogs side="right" className="z-[5] hidden xl:block" />

      <div className="pointer-events-none absolute left-6 top-6 z-20 flex items-center gap-2">
        <span className="animate-pulse font-data font-bold text-live">{"_>"}</span>
        <span className="font-data text-[12px] uppercase tracking-[0.2em] text-live/80">
          SYSTEM_OVERRIDE
        </span>
      </div>

      {/* Explicit flex centering — avoid utility-class ambiguity in embedded browsers */}
      <div
        className="relative z-20 px-4 py-16"
        style={{
          display: "flex",
          minHeight: "100dvh",
          width: "100%",
          alignItems: "center",
          justifyContent: "center",
          boxSizing: "border-box",
        }}
      >
        <div className="relative w-full" style={{ maxWidth: "28rem" }}>
          <div
            className="pointer-events-none absolute left-1/2 top-1/2 z-0 -translate-x-1/2 -translate-y-1/2 opacity-45 mix-blend-screen"
            style={{ width: "min(92vw, 28rem)", height: "min(92vw, 28rem)" }}
            aria-hidden
          >
            <div className="radar-scope relative h-full w-full">
              <div className="absolute inset-0 rounded-full border border-live/25" />
              <div className="absolute inset-[12%] rounded-full border border-live/15" />
              <div className="absolute inset-[28%] rounded-full border border-live/10" />
              <div className="absolute inset-[44%] rounded-full border border-live/8" />
              <div className="radar-crosshair absolute inset-0" />
              <div className="radar-sweep-beam absolute inset-0 rounded-full" />
              <div className="absolute left-1/2 top-1/2 size-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-live/80 shadow-[0_0_12px_var(--live)]" />
            </div>
          </div>

          <div className="relative z-10 flex w-full flex-col items-center">
            <div className="mb-8 w-full select-none text-center sm:mb-10">
              <h1
                className="glitch-3d type-display mx-auto font-display text-[clamp(3rem,12vw,5.5rem)] font-bold uppercase tracking-tight text-live"
                data-text="DATUM"
              >
                DATUM
              </h1>
              <p className="mx-auto mt-4 max-w-[22rem] text-balance font-data text-[13px] leading-relaxed text-live/55">
                Establish the truth of a web asset, then watch for the moment it stops being true.
              </p>
            </div>

            <section className="relative w-full rounded-md border border-live/20 bg-carbon/90 px-6 py-9 shadow-[0_0_30px_rgba(184,240,76,0.1)] backdrop-blur-md sm:px-10 sm:py-10">
              <RegistrationMarks />
              {formReady ? (
                mode === "signin" ? (
                  <SignInForm onSwitch={() => setMode("signup")} />
                ) : (
                  <SignUpForm onSwitch={() => setMode("signin")} />
                )
              ) : (
                <div className="min-h-[280px]" aria-busy="true" aria-label="Loading form" />
              )}
            </section>

            <p className="mt-5 text-center font-data text-[11px] tracking-wide text-live/40">
              {">"} build {BUILD_HASH} · SECURE SESSION_
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function SignInForm({ onSwitch }: { onSwitch: () => void }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [state, formAction, pending] = useActionState(signInAction, INITIAL);
  const [showHostedDialog, setShowHostedDialog] = useState(false);
  const [localHost, setLocalHost] = useState(false);
  const configError = searchParams.get("error") === "config";
  const authError = searchParams.get("error") === "auth";

  useEffect(() => {
    setLocalHost(isLocalHost());
  }, []);

  useEffect(() => {
    if (state.signedIn) {
      router.replace(state.next);
      router.refresh();
    }
  }, [state.signedIn, state.next, router]);

  useEffect(() => {
    // Local clones are not fully configured by design (no service-role / BYOK secrets).
    // On failed sign-in, steer users to the hosted deployment instead of a raw auth error.
    if (state.error && isLocalHost()) {
      setShowHostedDialog(true);
    }
  }, [state.error]);

  return (
    <form className="relative w-full space-y-5" action={formAction}>
      <input type="hidden" name="next" value={searchParams.get("next") ?? "/"} />
      <Honeypot />

      <div className="text-center sm:text-left">
        <p className="type-label !text-live/60">Authenticate</p>
        <h2 className="mt-1 type-h2 text-live">Terminal Access</h2>
      </div>

      {configError ? (
        <AuthBanner tone="critical">
          Local env incomplete. Stop the server, run `npm run setup`, then `npm run
          dev` again. If it still fails, delete `.env.local` and re-run setup. Scans
          need a private `SUPABASE_SERVICE_ROLE_KEY` from a teammate — or use{" "}
          <a href={HOSTED_APP_URL} className="underline underline-offset-2">
            {HOSTED_APP_URL.replace(/^https:\/\//, "")}
          </a>
          .
        </AuthBanner>
      ) : null}
      {authError ? (
        <AuthBanner tone="critical">Sign-in link expired or invalid. Try again.</AuthBanner>
      ) : null}
      {/* Localhost: suppress raw auth errors — dialog handles the message instead. */}
      {state.error && !localHost ? (
        <AuthBanner tone="critical">{state.error}</AuthBanner>
      ) : null}
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

      <Button
        type="submit"
        className="w-full !border-live !text-live hover:!bg-live/10"
        variant="secondary"
        disabled={pending}
      >
        {pending ? "Authenticating…" : "Authenticate"}
      </Button>

      <p className="type-small text-center text-text-dim">
        No clearance?{" "}
        <button
          type="button"
          onClick={onSwitch}
          className="font-data text-[12px] text-live underline-offset-2 hover:underline"
        >
          Request access
        </button>
      </p>

      {showHostedDialog ? (
        <HostedLoginDialog
          onClose={() => setShowHostedDialog(false)}
          onContinue={() => {
            window.location.assign(`${HOSTED_APP_URL}/login`);
          }}
        />
      ) : null}
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
    <form className="relative w-full space-y-5" action={formAction}>
      <Honeypot />

      <div className="text-center sm:text-left">
        <p className="type-label !text-live/60">Register</p>
        <h2 className="mt-1 type-h2 text-live">Request Access</h2>
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

      <Button
        type="submit"
        className="w-full !border-live !text-live hover:!bg-live/10"
        variant="secondary"
        disabled={pending}
      >
        {pending ? "Creating account…" : "Submit request"}
      </Button>

      <p className="type-small text-center text-text-dim">
        Already registered?{" "}
        <button
          type="button"
          onClick={onSwitch}
          className="font-data text-[12px] text-live underline-offset-2 hover:underline"
        >
          Sign in
        </button>
      </p>
    </form>
  );
}

function HostedLoginDialog({
  onClose,
  onContinue,
}: {
  onClose: () => void;
  onContinue: () => void;
}) {
  return (
    <div
      className="fixed inset-0 z-[80] flex items-center justify-center bg-void/80 px-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="hosted-login-title"
    >
      <div className="relative w-full max-w-md rounded-md border border-live/25 bg-carbon p-6 shadow-[0_0_40px_rgba(184,240,76,0.12)]">
        <RegistrationMarks />
        <p className="type-label !text-live/60">Local session</p>
        <h3 id="hosted-login-title" className="mt-1 type-h2 text-live">
          Use the hosted console
        </h3>
        <p className="mt-3 font-data text-[13px] leading-relaxed text-text-dim">
          Localhost is for development only. Private server secrets (service role, BYOK,
          cron) are not shipped in the repo by design, so full auth on a clone often
          fails. Sign in on the live deployment instead.
        </p>
        <div className="mt-6 flex flex-col gap-2 sm:flex-row sm:justify-end">
          <Button type="button" variant="ghost" onClick={onClose} className="w-full sm:w-auto">
            Stay here
          </Button>
          <Button
            type="button"
            variant="secondary"
            onClick={onContinue}
            className="w-full !border-live !text-live hover:!bg-live/10 sm:w-auto"
          >
            Open systemsiege.vercel.app
          </Button>
        </div>
      </div>
    </div>
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
  children: ReactNode;
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
