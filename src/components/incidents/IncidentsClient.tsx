"use client";

import { useMemo, useState, useEffect, useRef } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { AppShell } from "@/components/shell/AppShell";
import { Button } from "@/components/ui/Button";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { StatusLed } from "@/components/ui/StatusLed";
import { StatusPill } from "@/components/ui/StatusPill";
import { useToast } from "@/components/ui/Toast";
import { updateIncidentStatus } from "@/app/actions/datum";
import type { ShellContext } from "@/lib/data/shell";
import type { Incident, IncidentStatus } from "@/lib/types";
import { cn, formatClock, severityTone } from "@/lib/format";

function Mermaid({ chart }: { chart: string }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [svg, setSvg] = useState<string | null>(null);
  const [error, setError] = useState<boolean>(false);

  useEffect(() => {
    let active = true;
    
    const initMermaid = async () => {
      try {
        const globalWindow = window as unknown as {
          mermaid?: {
            initialize: (config: Record<string, unknown>) => void;
            render: (id: string, text: string) => Promise<{ svg: string }>;
          };
        };

        if (!globalWindow.mermaid) {
          await new Promise<void>((resolve, reject) => {
            const script = document.createElement("script");
            script.src = "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js";
            script.async = true;
            script.onload = () => resolve();
            script.onerror = () => reject(new Error("Failed to load Mermaid CDN"));
            document.body.appendChild(script);
          });
        }
        
        const mermaid = globalWindow.mermaid;
        if (mermaid) {
          mermaid.initialize({
            startOnLoad: false,
            theme: "dark",
            securityLevel: "loose",
          });

          if (active && containerRef.current) {
            const id = `mermaid-${Math.random().toString(36).substr(2, 9)}`;
            const cleanChart = chart
              .replace(/\\n/g, "\n")
              .replace(/flowchart TD/g, "graph TD");
            const { svg: renderedSvg } = await mermaid.render(id, cleanChart);
            if (active) {
              setSvg(renderedSvg);
            }
          }
        }
      } catch (err) {
        console.error("Mermaid rendering failed:", err);
        if (active) setError(true);
      }
    };

    initMermaid();

    return () => {
      active = false;
    };
  }, [chart]);

  if (error) {
    return (
      <pre className="font-mono text-[9px] text-text-faint bg-void p-3 rounded-sm border border-edge whitespace-pre-wrap overflow-auto max-h-40">
        {chart.replace(/\\n/g, "\n")}
      </pre>
    );
  }

  if (svg) {
    return (
      <div 
        className="flex justify-center p-2 [&>svg]:w-full [&>svg]:h-auto [&>svg]:max-h-60" 
        dangerouslySetInnerHTML={{ __html: svg }} 
      />
    );
  }

  return (
    <div ref={containerRef} className="font-mono text-[9px] text-text-faint bg-void p-3 rounded-sm border border-edge whitespace-pre-wrap overflow-auto max-h-40">
      {chart.replace(/\\n/g, "\n")}
    </div>
  );
}

interface IncidentsClientProps {
  shell: ShellContext;
  incidents: Incident[];
}

export function IncidentsClient({ shell, incidents: initial }: IncidentsClientProps) {
  const [rows, setRows] = useState(initial);
  const [filter, setFilter] = useState<"all" | "open" | "resolved">("all");
  const [drawer, setDrawer] = useState<Incident | null>(null);
  const { push } = useToast();
  const router = useRouter();

  const filtered = useMemo(() => {
    const sorted = [...rows].sort((a, b) => {
      const rank: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      return (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9);
    });
    if (filter === "all") return sorted;
    if (filter === "open") return sorted.filter((r) => r.status !== "resolved");
    return sorted.filter((r) => r.status === "resolved");
  }, [rows, filter]);

  async function setStatus(id: string, status: IncidentStatus) {
    const result = await updateIncidentStatus(id, status);
    if (!result.ok) {
      push(`UPDATE FAILED · ${result.error}`);
      return;
    }
    setRows((prev) => prev.map((r) => (r.id === id ? { ...r, status } : r)));
    push(`INCIDENT ${id.slice(0, 8)} · ${status.toUpperCase()}`);
    setDrawer((d) => (d && d.id === id ? { ...d, status } : d));
    router.refresh();
  }

  return (
    <AppShell crumbs={[{ label: "INCIDENTS" }]} shell={shell}>
      <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
        <div>
          <MonoEyebrow index="12">
            Incident feed · {String(filtered.filter((r) => r.status !== "resolved").length).padStart(2, "0")} open
          </MonoEyebrow>
          <h1 className="mt-2 type-h1 text-text">Incidents</h1>
        </div>
        <div className="flex gap-1">
          {(["all", "open", "resolved"] as const).map((f) => (
            <button
              key={f}
              type="button"
              onClick={() => setFilter(f)}
              className={cn(
                "rounded-sm border px-2.5 py-1 font-data text-[11px] uppercase tracking-wider",
                filter === f
                  ? "border-live/40 bg-slate-hi text-text"
                  : "border-edge text-text-faint hover:border-edge-hi",
              )}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="panel px-6 py-16 text-center font-data text-[12px] text-text-faint">
          No incidents recorded — defacement or critical findings will open one automatically.
        </div>
      ) : (
        <div className="panel overflow-x-auto">
          <table className="w-full min-w-[720px] text-left">
            <thead className="border-b border-edge bg-slate">
              <tr className="type-label">
                <th className="px-4 py-3 font-normal">Sev</th>
                <th className="px-4 py-3 font-normal">Asset</th>
                <th className="px-4 py-3 font-normal">Type</th>
                <th className="px-4 py-3 font-normal">Detected</th>
                <th className="px-4 py-3 font-normal">Status</th>
                <th className="px-4 py-3 font-normal">MTTD</th>
                <th className="px-4 py-3 font-normal">Assignee</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r) => (
                <tr
                  key={r.id}
                  onClick={() => setDrawer(r)}
                  className={cn(
                    "h-[38px] cursor-pointer border-b border-edge last:border-0 hover:bg-slate-hi",
                    (r.severity === "CRITICAL" || r.severity === "HIGH") &&
                      "shadow-[inset_2px_0_0_0_rgba(240,86,63,0.55)]",
                  )}
                >
                  <td className="px-4">
                    <StatusPill tone={severityTone(r.severity)}>{r.severity}</StatusPill>
                  </td>
                  <td className="px-4 text-[14px] text-text">{r.assetName}</td>
                  <td className="px-4 font-data text-[12px] text-text-dim">{r.type}</td>
                  <td className="px-4 font-data text-[12px] text-text-faint">
                    {formatClock(r.detectedAt)}
                  </td>
                  <td className="px-4">
                    <span className="inline-flex items-center gap-2">
                      <StatusLed
                        posture={
                          r.status === "resolved"
                            ? "secure"
                            : r.severity === "CRITICAL" || r.severity === "HIGH"
                              ? "critical"
                              : "watch"
                        }
                      />
                      <span className="font-data text-[11px] uppercase text-text-dim">
                        {r.status}
                      </span>
                    </span>
                  </td>
                  <td className="px-4 font-data text-[12px] text-text">{r.mttdSec}s</td>
                  <td className="px-4 font-data text-[12px] text-text-dim">
                    {r.assignee ?? "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {drawer ? (
        <div className="fixed inset-0 z-50 flex justify-end">
          <button
            type="button"
            className="absolute inset-0 bg-void/70"
            aria-label="Close"
            onClick={() => setDrawer(null)}
          />
          <aside className="relative flex h-full w-full max-w-md flex-col border-l border-edge bg-carbon p-5">
            <MonoEyebrow index="13">Incident · {drawer.id.slice(0, 8)}</MonoEyebrow>
            <h2 className="mt-2 type-h2 text-text">{drawer.type}</h2>
            <p className="mt-2 border-b border-edge pb-2 font-data text-[12px] text-text-dim">
              {drawer.assetName} · {formatClock(drawer.detectedAt)}
            </p>

            <div className="flex-1 overflow-y-auto mt-4 pr-1 space-y-4 font-data text-[12px]">
              {/* MTTD Stats */}
              <div className="rounded-sm border border-edge bg-void/40 p-3">
                <div className="flex justify-between items-center">
                  <span className="text-text-faint uppercase font-bold text-[10px]">TIME TO DETECT (MTTD)</span>
                  <span className={cn("font-bold text-[13px] tracking-wider px-1.5 py-0.5 rounded-sm bg-critical/15 text-critical border border-critical/30")}>
                    {drawer.mttdSec}s (LIVE MATCH)
                  </span>
                </div>
              </div>

              {/* AI Attribution Card */}
              {drawer.aiVerdict ? (
                <div className="space-y-4">
                  <div className="rounded-sm border border-edge bg-void/25 p-3 space-y-2">
                    <p className="font-bold text-magenta text-[10px] uppercase tracking-wider">👤 Threat Actor Profile</p>
                    <p className="text-text leading-relaxed italic">
                      &ldquo;{drawer.aiVerdict.threatActorProfile || "Intent analysis pending..."}&rdquo;
                    </p>
                  </div>

                  <div className="rounded-sm border border-edge bg-void/25 p-3 space-y-2">
                    <p className="font-bold text-watch text-[10px] uppercase tracking-wider">⚔️ Likely Attack Vector</p>
                    <p className="text-text-dim leading-relaxed">
                      {drawer.aiVerdict.likelyAttackVector || "Vector analysis pending..."}
                    </p>
                  </div>

                  {drawer.aiVerdict.mermaidGraph && (
                    <div className="rounded-sm border border-edge bg-void/25 p-3 space-y-2">
                      <p className="font-bold text-live text-[10px] uppercase tracking-wider">📊 Probabilistic Attack Path</p>
                      <div className="mt-2 bg-void/40 rounded-sm border border-edge/60">
                        <Mermaid chart={drawer.aiVerdict.mermaidGraph} />
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-center py-6 text-text-faint italic border border-dashed border-edge rounded-sm">
                  Threat attribution analysis offline or establishing baseline.
                </div>
              )}
            </div>

            {shell.isAnalyst ? (
              <div className="mt-4 space-y-2 border-t border-edge pt-3">
                <Button className="w-full" onClick={() => setStatus(drawer.id, "acknowledged")}>
                  Acknowledge
                </Button>
                <Button
                  variant="secondary"
                  className="w-full"
                  onClick={() => setStatus(drawer.id, "resolved")}
                >
                  Mark fixed
                </Button>
              </div>
            ) : null}
            <Link
              href={`/assets/${drawer.assetId}`}
              className="mt-4 block text-center font-data text-[12px] text-scan underline-offset-2 hover:underline"
            >
              Open asset detail
            </Link>
          </aside>
        </div>
      ) : null}
    </AppShell>
  );
}
