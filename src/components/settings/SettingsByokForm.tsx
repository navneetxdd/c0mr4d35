"use client";

import { useActionState, useEffect } from "react";
import { saveByokKeysAction, type ByokActionState } from "@/app/actions/byok";
import type { ByokKeyStatus } from "@/lib/auth/byok";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { useToast } from "@/components/ui/Toast";

interface SettingsByokFormProps {
  initial: ByokKeyStatus;
}

const empty: ByokActionState = {
  ok: false,
  error: null,
  message: null,
  status: null,
};

const GEMINI_KEY_URL = "https://aistudio.google.com/apikey";
const SHODAN_KEY_URL = "https://account.shodan.io/";

export function SettingsByokForm({ initial }: SettingsByokFormProps) {
  const { push } = useToast();
  const [state, action, pending] = useActionState(saveByokKeysAction, {
    ...empty,
    status: initial,
  });

  const status = state.status ?? initial;

  useEffect(() => {
    if (state.message) push(state.message);
    if (state.error) push(state.error);
  }, [state.message, state.error, push]);

  return (
    <section id="api-keys" className="panel mt-6 scroll-mt-24 p-4">
      <MonoEyebrow index="17">Bring your own keys</MonoEyebrow>
      <h2 className="mt-2 type-h2 text-text">API keys</h2>
      <p className="mt-2 max-w-2xl font-body text-[14px] leading-relaxed text-text-dim">
        Keys are stored server-side per account and never returned to the browser after save. Gemini
        powers the AI verdict. Shodan enriches ports, CVEs, and subdomains (InternetDB still runs
        without a Shodan key). You can leave these blank for now — scans still work; AI / Shodan
        enrichment unlock when you add keys.
      </p>

      <div className="mt-4 flex flex-wrap gap-3">
        <a
          href={GEMINI_KEY_URL}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center border border-edge bg-panel px-3 py-2 font-data text-[11px] tracking-[0.06em] text-text transition-colors hover:border-text-faint hover:bg-void"
        >
          OPEN GEMINI API KEYS →
        </a>
        <a
          href={SHODAN_KEY_URL}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center border border-edge bg-panel px-3 py-2 font-data text-[11px] tracking-[0.06em] text-text transition-colors hover:border-text-faint hover:bg-void"
        >
          OPEN SHODAN ACCOUNT →
        </a>
      </div>

      <form action={action} className="mt-5 grid gap-5">
        <div>
          <div className="mb-2 flex items-center justify-between gap-3">
            <span className="type-label">Gemini</span>
            <StatusPill
              ok={status.geminiConfigured || status.geminiEnvConfigured}
              label={
                status.geminiConfigured
                  ? "account key set"
                  : status.geminiEnvConfigured
                    ? "deploy env fallback"
                    : "not configured"
              }
            />
          </div>
          <Input
            label="Google Gemini API key"
            name="geminiApiKey"
            type="password"
            autoComplete="off"
            placeholder={status.geminiConfigured ? "Leave blank to keep current key" : "AIza…"}
            disabled={pending}
            hint="Provider: Google Gemini · Model: gemini-2.5-flash"
          />
          <label className="mt-2 flex items-center gap-2 font-data text-[11px] text-text-faint">
            <input type="checkbox" name="clearGemini" disabled={pending} />
            Clear saved Gemini key
          </label>
          <p className="mt-1 font-data text-[11px] text-text-faint">
            No key yet?{" "}
            <a className="underline hover:text-text" href={GEMINI_KEY_URL} target="_blank" rel="noreferrer">
              Create one in Google AI Studio
            </a>
          </p>
        </div>

        <div>
          <div className="mb-2 flex items-center justify-between gap-3">
            <span className="type-label">Shodan</span>
            <StatusPill
              ok={status.shodanConfigured}
              label={status.shodanConfigured ? "account key set" : "not configured"}
            />
          </div>
          <Input
            label="Shodan API key"
            name="shodanApiKey"
            type="password"
            autoComplete="off"
            placeholder={status.shodanConfigured ? "Leave blank to keep current key" : "Shodan API key"}
            disabled={pending}
            hint="Used for Shodan host + DNS domain APIs"
          />
          <label className="mt-2 flex items-center gap-2 font-data text-[11px] text-text-faint">
            <input type="checkbox" name="clearShodan" disabled={pending} />
            Clear saved Shodan key
          </label>
          <p className="mt-1 font-data text-[11px] text-text-faint">
            No key yet?{" "}
            <a className="underline hover:text-text" href={SHODAN_KEY_URL} target="_blank" rel="noreferrer">
              Open Shodan account (API key on dashboard)
            </a>
          </p>
        </div>

        <div className="flex justify-end">
          <Button type="submit" disabled={pending}>
            {pending ? "Saving…" : "Save keys"}
          </Button>
        </div>
      </form>
    </section>
  );
}

function StatusPill({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className={
        ok
          ? "font-data text-[11px] tracking-[0.06em] text-secure"
          : "font-data text-[11px] tracking-[0.06em] text-watch"
      }
    >
      {label.toUpperCase()}
    </span>
  );
}
