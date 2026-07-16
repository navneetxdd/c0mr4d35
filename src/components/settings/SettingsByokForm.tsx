"use client";

import {
  KEY_MASK_SENTINEL,
  type ByokKeyStatus,
} from "@/lib/auth/byok-shared";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { useToast } from "@/components/ui/Toast";
import {
  saveGeminiKeyAction,
  saveShodanKeyAction,
  type ByokActionState,
} from "@/app/actions/byok";
import { useActionState, useEffect, useState } from "react";

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
const SHODAN_MEMBER_URL = "https://account.shodan.io/billing/member";

export function SettingsByokForm({ initial }: SettingsByokFormProps) {
  const { push } = useToast();
  const [geminiState, geminiAction, geminiPending] = useActionState(saveGeminiKeyAction, {
    ...empty,
    status: initial,
  });
  const [shodanState, shodanAction, shodanPending] = useActionState(saveShodanKeyAction, {
    ...empty,
    status: initial,
  });

  const status: ByokKeyStatus = {
    geminiConfigured:
      geminiState.status?.geminiConfigured ??
      shodanState.status?.geminiConfigured ??
      initial.geminiConfigured,
    shodanConfigured:
      shodanState.status?.shodanConfigured ??
      geminiState.status?.shodanConfigured ??
      initial.shodanConfigured,
    geminiEnvConfigured:
      geminiState.status?.geminiEnvConfigured ??
      shodanState.status?.geminiEnvConfigured ??
      initial.geminiEnvConfigured,
  };

  const [geminiValue, setGeminiValue] = useState(
    initial.geminiConfigured ? KEY_MASK_SENTINEL : "",
  );
  const [shodanValue, setShodanValue] = useState(
    initial.shodanConfigured ? KEY_MASK_SENTINEL : "",
  );

  useEffect(() => {
    if (status.geminiConfigured && !geminiValue) setGeminiValue(KEY_MASK_SENTINEL);
    if (!status.geminiConfigured && geminiValue === KEY_MASK_SENTINEL) setGeminiValue("");
  }, [status.geminiConfigured, geminiValue]);

  useEffect(() => {
    if (status.shodanConfigured && !shodanValue) setShodanValue(KEY_MASK_SENTINEL);
    if (!status.shodanConfigured && shodanValue === KEY_MASK_SENTINEL) setShodanValue("");
  }, [status.shodanConfigured, shodanValue]);

  useEffect(() => {
    if (geminiState.message) push(geminiState.message);
    if (geminiState.error) push(geminiState.error);
  }, [geminiState.message, geminiState.error, push]);

  useEffect(() => {
    if (shodanState.message) push(shodanState.message);
    if (shodanState.error) push(shodanState.error);
  }, [shodanState.message, shodanState.error, push]);

  useEffect(() => {
    if (geminiState.ok && geminiState.status?.geminiConfigured) {
      setGeminiValue(KEY_MASK_SENTINEL);
    }
    if (geminiState.ok && geminiState.status && !geminiState.status.geminiConfigured) {
      setGeminiValue("");
    }
  }, [geminiState.ok, geminiState.status]);

  useEffect(() => {
    if (shodanState.ok && shodanState.status?.shodanConfigured) {
      setShodanValue(KEY_MASK_SENTINEL);
    }
    if (shodanState.ok && shodanState.status && !shodanState.status.shodanConfigured) {
      setShodanValue("");
    }
  }, [shodanState.ok, shodanState.status]);

  return (
    <section id="api-keys" className="panel mt-6 scroll-mt-24 p-4">
      <MonoEyebrow index="17">Bring your own keys</MonoEyebrow>
      <h2 className="mt-2 type-h2 text-text">API keys</h2>
      <p className="mt-2 max-w-2xl font-body text-[14px] leading-relaxed text-text-dim">
        Keys are encrypted at rest for your account only and never sent back to the browser.
        Dots mean a key is stored — paste a new value only when rotating. Save each provider
        separately if you only have one key.
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

      <form action={geminiAction} className="mt-6 border-t border-edge pt-5">
        <div className="mb-2 flex items-center justify-between gap-3">
          <span className="type-label">Gemini</span>
          <StatusPill
            ok={status.geminiConfigured || status.geminiEnvConfigured}
            label={
              status.geminiConfigured
                ? "saved on account"
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
          value={geminiValue}
          onChange={(e) => setGeminiValue(e.target.value)}
          onFocus={() => {
            if (geminiValue === KEY_MASK_SENTINEL) setGeminiValue("");
          }}
          onBlur={() => {
            if (!geminiValue && status.geminiConfigured) setGeminiValue(KEY_MASK_SENTINEL);
          }}
          placeholder={status.geminiConfigured ? KEY_MASK_SENTINEL : "AQ.… or AIza…"}
          disabled={geminiPending}
          hint="Encrypted per user · Model: gemini-2.5-flash"
        />
        <label className="mt-2 flex items-center gap-2 font-data text-[11px] text-text-faint">
          <input type="checkbox" name="clearGemini" disabled={geminiPending} />
          Clear saved Gemini key
        </label>
        <p className="mt-1 font-data text-[11px] text-text-faint">
          <a className="underline hover:text-text" href={GEMINI_KEY_URL} target="_blank" rel="noreferrer">
            Create / manage key in Google AI Studio
          </a>
        </p>
        <div className="mt-3 flex justify-end">
          <Button type="submit" disabled={geminiPending}>
            {geminiPending ? "Saving…" : "Save Gemini key"}
          </Button>
        </div>
      </form>

      <form action={shodanAction} className="mt-6 border-t border-edge pt-5">
        <div className="mb-2 flex items-center justify-between gap-3">
          <span className="type-label">Shodan</span>
          <StatusPill
            ok={status.shodanConfigured}
            label={status.shodanConfigured ? "saved on account" : "not configured"}
          />
        </div>
        <Input
          label="Shodan API key"
          name="shodanApiKey"
          type="password"
          autoComplete="off"
          value={shodanValue}
          onChange={(e) => setShodanValue(e.target.value)}
          onFocus={() => {
            if (shodanValue === KEY_MASK_SENTINEL) setShodanValue("");
          }}
          onBlur={() => {
            if (!shodanValue && status.shodanConfigured) setShodanValue(KEY_MASK_SENTINEL);
          }}
          placeholder={status.shodanConfigured ? KEY_MASK_SENTINEL : "Shodan API key"}
          disabled={shodanPending}
          hint="InternetDB ports/CVEs work without a key. Host + DNS APIs need Membership."
        />
        <label className="mt-2 flex items-center gap-2 font-data text-[11px] text-text-faint">
          <input type="checkbox" name="clearShodan" disabled={shodanPending} />
          Clear saved Shodan key
        </label>
        <p className="mt-1 font-data text-[11px] text-text-faint">
          <a className="underline hover:text-text" href={SHODAN_KEY_URL} target="_blank" rel="noreferrer">
            Shodan account dashboard
          </a>
          {" · "}
          <a className="underline hover:text-text" href={SHODAN_MEMBER_URL} target="_blank" rel="noreferrer">
            Membership (host/DNS API)
          </a>
        </p>
        <div className="mt-3 flex justify-end">
          <Button type="submit" disabled={shodanPending}>
            {shodanPending ? "Saving…" : "Save Shodan key"}
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
