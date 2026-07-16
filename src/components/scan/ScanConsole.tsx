"use client";

import { useState } from "react";
import { AppShell } from "@/components/shell/AppShell";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";
import { StatusPill } from "@/components/ui/StatusPill";
import { StatusLed } from "@/components/ui/StatusLed";
import type { ShellContext } from "@/lib/data/shell";
import type { ScanApiResponse, SafeScanResult } from "@/lib/scan/api-types";
import type { AiVerdict } from "@/lib/ai/gemini";
import type { Risk } from "@/lib/scan/risk";
import type { ScanStageEvent } from "@/lib/scan/progress";
import { cn } from "@/lib/format";

type RunState =
  | { phase: "idle" }
  | { phase: "scanning"; pct: number; stage: string; message: string }
  | { phase: "done"; scan: SafeScanResult; verdict?: AiVerdict }
  | { phase: "error"; message: string };

const riskTone: Record<Risk, "critical" | "watch" | "scan" | "secure" | "neutral"> = {
  critical: "critical",
  high: "critical",
  medium: "watch",
  low: "scan",
  info: "neutral",
};

const CATEGORY_ORDER = [
  "DEFACEMENT",
  "BEHAVIOR",
  "PORTS",
  "SUBDOMAINS",
  "HEADERS",
  "COOKIES",
  "CORS",
  "CONTENT",
  "METHODS",
  "TLS",
  "DNS",
  "EXPOSED PATHS",
  "CVE",
] as const;

interface ScanConsoleProps {
  shell: ShellContext;
  baselineHtml?: string | null;
}

export function ScanConsole({ shell, baselineHtml = null }: ScanConsoleProps) {
  const [target, setTarget] = useState("");
  const [state, setState] = useState<RunState>({ phase: "idle" });

  const adHocShell: ShellContext = {
    ...shell,
    posture: state.phase === "done" ? state.scan.posture : shell.posture,
  };

  async function run() {
    setState({ phase: "scanning", pct: 1, stage: "start", message: "Starting assessment…" });
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "text/event-stream" },
        body: JSON.stringify({
          target,
          withAi: true,
          stream: true,
          baselineHtml: baselineHtml || undefined,
        }),
      });

      const contentType = res.headers.get("content-type") ?? "";
      if (!contentType.includes("text/event-stream")) {
        const data = (await res.json()) as ScanApiResponse;
        if (!data.ok) {
          setState({ phase: "error", message: data.error });
          return;
        }
        setState({ phase: "done", scan: data.scan, verdict: data.verdict });
        return;
      }

      if (!res.body) {
        setState({ phase: "error", message: "Empty scan stream" });
        return;
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let currentEvent = "message";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const chunks = buffer.split("\n\n");
        buffer = chunks.pop() ?? "";

        for (const chunk of chunks) {
          const lines = chunk.split("\n");
          let dataLine = "";
          for (const line of lines) {
            if (line.startsWith("event:")) currentEvent = line.slice(6).trim();
            if (line.startsWith("data:")) dataLine += line.slice(5).trim();
          }
          if (!dataLine) continue;

          let payload: unknown;
          try {
            payload = JSON.parse(dataLine);
          } catch {
            continue;
          }

          if (currentEvent === "stage") {
            const stage = payload as ScanStageEvent;
            setState({
              phase: "scanning",
              pct: stage.pct,
              stage: stage.stage,
              message: stage.artifact ? `${stage.message} · ${stage.artifact}` : stage.message,
            });
          } else if (currentEvent === "result") {
            const data = payload as ScanApiResponse;
            if (!data.ok) {
              setState({ phase: "error", message: data.error });
            } else {
              setState({ phase: "done", scan: data.scan, verdict: data.verdict });
            }
          } else if (currentEvent === "error") {
            const data = payload as { error?: string };
            setState({ phase: "error", message: data.error ?? "Scan failed" });
          }
        }
      }
    } catch {
      setState({ phase: "error", message: "Network error — could not reach the scanner." });
    }
  }

  return (
    <AppShell crumbs={[{ label: "COMMAND" }, { label: "LIVE SCAN" }]} shell={adHocShell}>
      <div className="mb-5">
        <MonoEyebrow index="00">Assessment engine</MonoEyebrow>
        <h1 className="mt-2 type-h1 text-text">Live scan</h1>
        <p className="mt-2 max-w-2xl type-small text-text-dim">
          Live probes only — SSRF-guarded fetch, DOM/visual baseline comparison, header/TLS/DNS
          hygiene, TCP port connects, Certificate Transparency + DNS subdomain discovery. Every
          finding carries observed evidence; nothing is fixture-driven.
        </p>
      </div>

      <section className="panel relative mb-4 p-4">
        <RegistrationMarks />
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <div className="flex-1">
            <Input
              label="Target URL"
              placeholder="https://example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="font-data"
              onKeyDown={(e) => {
                if (e.key === "Enter" && target.length > 3 && state.phase !== "scanning") run();
              }}
            />
          </div>
          <Button
            onClick={run}
            disabled={target.length < 4 || state.phase === "scanning" || !shell.isAnalyst}
            className="sm:w-40"
          >
            {state.phase === "scanning" ? "Scanning…" : "Run assessment"}
          </Button>
        </div>
        <p className="mt-2 type-data-sm text-text-faint">
          Public hosts only · private / loopback / metadata ranges are rejected before any request.
          {baselineHtml
            ? " · Baseline HTML attached for defacement detection."
            : " · First ad-hoc run establishes a baseline for future comparison."}
        </p>
      </section>

      {state.phase === "scanning" ? (
        <ProgressPanel pct={state.pct} stage={state.stage} message={state.message} />
      ) : null}

      {state.phase === "error" ? (
        <div className="panel border-critical/50 p-4">
          <p className="font-data text-[13px] text-critical">✗ {state.message}</p>
        </div>
      ) : null}

      {state.phase === "done" ? <Results scan={state.scan} verdict={state.verdict} /> : null}
    </AppShell>
  );
}

function ProgressPanel({
  pct,
  stage,
  message,
}: {
  pct: number;
  stage: string;
  message: string;
}) {
  return (
    <section className="panel relative mb-4 p-4">
      <RegistrationMarks />
      <MonoEyebrow index="00">Progress</MonoEyebrow>
      <div className="mt-3 flex items-center justify-between gap-3">
        <p className="font-data text-[12px] text-text">{message}</p>
        <p className="font-data text-[12px] text-text-faint">
          {pct}% · {stage.toUpperCase()}
        </p>
      </div>
      <div className="mt-3 h-2 overflow-hidden rounded-sm bg-void">
        <div className="h-full bg-live transition-[width] duration-300" style={{ width: `${pct}%` }} />
      </div>
    </section>
  );
}

function Results({ scan, verdict }: { scan: SafeScanResult; verdict?: AiVerdict }) {
  const tone =
    scan.posture === "critical" ? "critical" : scan.posture === "watch" ? "watch" : "secure";
  const defacementFindings = scan.findings.filter((f) => f.category === "DEFACEMENT");
  const hygieneFindings = scan.findings.filter((f) => f.category !== "DEFACEMENT");

  return (
    <div className="grid gap-4 lg:grid-cols-[1.4fr_0.9fr]">
      <div className="flex flex-col gap-4">
        <section className={cn("panel relative p-5", tone === "critical" && "glow-critical")}>
          <RegistrationMarks />
          <div className="flex flex-wrap items-end justify-between gap-3">
            <div>
              <MonoEyebrow index="01">Posture</MonoEyebrow>
              <p
                className={cn(
                  "mt-2 type-h1",
                  tone === "critical" ? "text-critical" : tone === "watch" ? "text-watch" : "text-secure",
                )}
              >
                {scan.posture.toUpperCase()}
              </p>
              <p className="mt-1 font-data text-[12px] text-text-dim">{scan.finalHost}</p>
            </div>
            <div className="text-right">
              <p className="type-data-lg text-text">{scan.postureScore}</p>
              <p className="type-data-sm text-text-faint">SCORE / 100</p>
            </div>
          </div>
          <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Metric label="HTTP" value={String(scan.httpStatus)} />
            <Metric label="DOM DRIFT" value={`${scan.driftPct}%`} />
            <Metric label="PAGES" value={String(scan.pagesScanned ?? 1)} />
            <Metric label="ELAPSED" value={`${(scan.elapsedMs / 1000).toFixed(1)}s`} />
          </div>
          {scan.redirectedTo ? (
            <p className="mt-3 type-data-sm text-text-faint">
              REDIRECT · {scan.httpStatus} → {scan.redirectedTo}
            </p>
          ) : null}
          {scan.fingerprint ? (
            <p className="mt-1 type-data-sm text-text-faint">STACK · {scan.fingerprint}</p>
          ) : null}
        </section>

        <EvidencePanel scan={scan} />
        <ReconProofPanel scan={scan} />
        <FindingsPanel
          title={`Defacement signals · ${String(defacementFindings.length).padStart(2, "0")}`}
          findings={defacementFindings}
          empty="No defacement signals — baseline held or first observation."
        />
        <FindingsPanel
          title={`Hygiene & recon · ${String(hygieneFindings.length).padStart(2, "0")}`}
          findings={hygieneFindings}
          empty="No hygiene/recon findings."
        />
      </div>

      <VerdictPanel verdict={verdict} />
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-sm border border-edge bg-void/40 px-3 py-2">
      <p className="type-data-sm text-text-faint">{label}</p>
      <p className="mt-0.5 truncate font-data text-[13px] text-text">{value}</p>
    </div>
  );
}

function EvidencePanel({ scan }: { scan: SafeScanResult }) {
  return (
    <section className="panel relative p-4">
      <RegistrationMarks />
      <MonoEyebrow index="02">Evidence state</MonoEyebrow>
      <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="BASELINE" value={(scan.baselineState ?? "none").toUpperCase()} />
        <Metric
          label="VISUAL DRIFT"
          value={scan.visualDriftPct != null ? `${scan.visualDriftPct}%` : "N/A"}
        />
        <Metric
          label="FAVICON"
          value={scan.faviconChanged ? "CHANGED" : scan.faviconHash ? "STABLE" : "N/A"}
        />
        <Metric label="STACK" value={scan.fingerprint ?? "—"} />
      </div>

      {scan.screenshotUrl || scan.baselineScreenshotUrl || scan.diffUrl ? (
        <div className="mt-4 grid gap-3 md:grid-cols-3">
          <EvidenceCapture label="BASELINE" src={scan.baselineScreenshotUrl ?? null} />
          <EvidenceCapture label="CURRENT" src={scan.screenshotUrl ?? null} />
          <EvidenceCapture label="PIXEL DIFF" src={scan.diffUrl ?? null} />
        </div>
      ) : null}

      {scan.evidenceNotes?.length ? (
        <div className="mt-4 rounded-sm border border-edge bg-void/40 p-3">
          <p className="type-label mb-2">Notes</p>
          <ul className="space-y-1">
            {scan.evidenceNotes.map((note) => (
              <li key={note} className="font-data text-[11px] text-text-faint">
                {note}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}

function ReconProofPanel({ scan }: { scan: SafeScanResult }) {
  const openPorts = (scan.ports ?? []).filter((p) => p.state === "open");
  const subs = scan.subdomains ?? [];
  if (!openPorts.length && !subs.length) return null;

  return (
    <section className="panel p-4">
      <MonoEyebrow index="02">Live recon proof</MonoEyebrow>
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div className="overflow-auto rounded-sm border border-edge">
          <p className="border-b border-edge px-3 py-2 type-label">Open TCP ports</p>
          {openPorts.length ? (
            <table className="w-full text-left font-data text-[11px]">
              <thead className="text-text-faint">
                <tr>
                  <th className="px-3 py-1">PORT</th>
                  <th className="px-3 py-1">RTT</th>
                  <th className="px-3 py-1">PROBED</th>
                </tr>
              </thead>
              <tbody>
                {openPorts.map((p) => (
                  <tr key={p.port} className="border-t border-edge">
                    <td className="px-3 py-1 text-text">{p.port}</td>
                    <td className="px-3 py-1 text-text">{p.rttMs}ms</td>
                    <td className="px-3 py-1 text-text-faint">{p.probedAt}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="px-3 py-3 font-data text-[11px] text-text-faint">No open ports in probed set.</p>
          )}
        </div>
        <div className="overflow-auto rounded-sm border border-edge">
          <p className="border-b border-edge px-3 py-2 type-label">Subdomains</p>
          {subs.length ? (
            <table className="w-full text-left font-data text-[11px]">
              <thead className="text-text-faint">
                <tr>
                  <th className="px-3 py-1">NAME</th>
                  <th className="px-3 py-1">SOURCE</th>
                  <th className="px-3 py-1">IPS</th>
                </tr>
              </thead>
              <tbody>
                {subs.slice(0, 30).map((s) => (
                  <tr key={s.subdomain} className="border-t border-edge">
                    <td className="px-3 py-1 text-text">{s.subdomain}</td>
                    <td className="px-3 py-1 text-text">{s.source}</td>
                    <td className="px-3 py-1 text-text-faint">{s.ips.join(", ") || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="px-3 py-3 font-data text-[11px] text-text-faint">No subdomains discovered.</p>
          )}
        </div>
      </div>
    </section>
  );
}

function FindingsPanel({
  title,
  findings,
  empty,
}: {
  title: string;
  findings: SafeScanResult["findings"];
  empty: string;
}) {
  return (
    <section className="panel">
      <div className="border-b border-edge px-4 py-3">
        <MonoEyebrow index="02">{title}</MonoEyebrow>
      </div>
      {findings.length === 0 ? (
        <div className="px-4 py-8 text-center">
          <p className="font-data text-[13px] text-secure">{empty}</p>
        </div>
      ) : (
        <div className="divide-y divide-edge">
          {CATEGORY_ORDER.map((cat) => {
            const rows = findings.filter((f) => f.category === cat);
            if (!rows.length) return null;
            return (
              <div key={cat} className="px-4 py-3">
                <p className="type-label mb-2">{cat}</p>
                <ul className="space-y-2">
                  {rows.map((f) => (
                    <li key={f.id} className="rounded-sm border border-edge bg-void/40 px-3 py-2.5">
                      <div className="flex items-start gap-2">
                        <StatusPill tone={riskTone[f.risk]}>{f.risk.toUpperCase()}</StatusPill>
                        <span className="min-w-0 flex-1 font-data text-[12px] text-text">{f.title}</span>
                      </div>
                      <p className="mt-1.5 type-small text-text-dim">{f.detail}</p>
                      {f.url ? (
                        <p className="mt-1 font-data text-[11px] text-text-faint">OBSERVED ON · {f.url}</p>
                      ) : null}
                      {f.evidence ? (
                        <p className="mt-1 font-data text-[11px] text-text-faint">EVIDENCE · {f.evidence}</p>
                      ) : null}
                      <p className="mt-1 type-data-sm text-text-faint">REMEDIATION · {f.remediation}</p>
                      {f.reference ? (
                        <a
                          href={f.reference}
                          target="_blank"
                          rel="noreferrer"
                          className="mt-1 inline-block font-data text-[11px] text-scan underline-offset-2 hover:underline"
                        >
                          {f.reference}
                        </a>
                      ) : null}
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

function VerdictPanel({ verdict }: { verdict?: AiVerdict }) {
  if (!verdict || !verdict.available) {
    return (
      <section className="panel relative p-4">
        <RegistrationMarks />
        <MonoEyebrow index="03">AI verdict</MonoEyebrow>
        <p className="mt-4 font-data text-[12px] uppercase tracking-wider text-text-dim">
          AI ENRICHMENT UNAVAILABLE
        </p>
        <p className="mt-2 type-small text-text-dim">
          {verdict?.error ? `Reason: ${verdict.error}. ` : ""}
          Findings on the left are authoritative — detection does not depend on the AI call.
        </p>
      </section>
    );
  }

  const tone =
    verdict.verdict === "DEFACEMENT" || verdict.verdict === "AT RISK"
      ? "critical"
      : verdict.verdict === "DRIFT DETECTED"
        ? "watch"
        : "secure";

  return (
    <section className="panel relative p-4">
      <RegistrationMarks />
      <MonoEyebrow index="03">AI verdict</MonoEyebrow>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <StatusPill tone={tone}>{verdict.verdict}</StatusPill>
        <span className="font-data text-[11px] text-text-faint">GEMINI 2.5 FLASH</span>
      </div>
      <div className="mt-4">
        <div className="flex items-center justify-between">
          <span className="type-label">Confidence</span>
          <span className="font-data text-[12px] text-text">{Math.round(verdict.confidence * 100)}%</span>
        </div>
        <div className="mt-1.5 h-1.5 overflow-hidden rounded-sm bg-void">
          <div
            className={cn(
              "h-full rounded-sm",
              tone === "critical" ? "bg-critical" : tone === "watch" ? "bg-watch" : "bg-secure",
            )}
            style={{ width: `${verdict.confidence * 100}%` }}
          />
        </div>
      </div>
      <p className="mt-4 type-small text-text-dim">{verdict.summary}</p>

      {verdict.prioritizedRisks.length ? (
        <div className="mt-4 border-t border-edge pt-3">
          <p className="type-label mb-2">Prioritized risks</p>
          <ul className="space-y-2">
            {verdict.prioritizedRisks.map((r, i) => (
              <li key={i} className="flex items-start gap-2">
                <StatusLed posture="critical" />
                <div>
                  <p className="font-data text-[12px] text-text">{r.title}</p>
                  <p className="type-data-sm text-text-faint">{r.why}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {verdict.recommendedActions.length ? (
        <div className="mt-4 border-t border-edge pt-3">
          <p className="type-label mb-2">Recommended actions</p>
          <ul className="space-y-1.5">
            {verdict.recommendedActions.map((a, i) => (
              <li key={i} className="font-data text-[12px] text-text-dim">
                → {a}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}

function EvidenceCapture({ label, src }: { label: string; src: string | null }) {
  return (
    <div className="overflow-hidden rounded-sm border border-edge bg-void">
      <div className="border-b border-edge px-2 py-1 font-data text-[10px] text-text-faint">
        {label}
      </div>
      {src ? (
        // eslint-disable-next-line @next/next/no-img-element
        <img src={src} alt={label} className="aspect-16/10 w-full object-cover" />
      ) : (
        <div className="flex aspect-16/10 items-center justify-center font-data text-[10px] text-text-faint">
          No image
        </div>
      )}
    </div>
  );
}
