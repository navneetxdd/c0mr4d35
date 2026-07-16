"use client";

import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";
import { BUILD_HASH } from "@/lib/fixtures";
import { createClient } from "@/lib/supabase/client";

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!email.includes("@") || password.length < 6) {
      setError("Enter a valid email and a password of at least 6 characters");
      return;
    }
    setLoading(true);
    try {
      const supabase = createClient();
      const { error: authError } = await supabase.auth.signInWithPassword({ email, password });
      if (authError) {
        setError("Invalid credentials");
        setLoading(false);
        return;
      }
      const next = searchParams.get("next") || "/";
      router.push(next.startsWith("/") ? next : "/");
      router.refresh();
    } catch {
      setError("Sign-in is unavailable — check the server configuration");
      setLoading(false);
    }
  }

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
        <form className="relative w-full max-w-md space-y-5" onSubmit={handleSubmit}>
          <div>
            <p className="type-label">Authenticate</p>
            <h1 className="mt-2 type-h1 text-text">Sign in</h1>
            <p className="mt-2 type-small text-text-dim lg:hidden">
              Establish the truth. Measure the drift.
            </p>
          </div>
          <Input
            label="Email"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            error={error ? " " : undefined}
          />
          <Input
            label="Password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            error={error ?? undefined}
          />
          <Button type="submit" className="w-full" disabled={loading}>
            {loading ? "Authenticating…" : "Authenticate"}
          </Button>
        </form>
      </section>
    </div>
  );
}
