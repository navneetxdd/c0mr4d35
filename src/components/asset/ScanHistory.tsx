"use client";

import type { ScanEntry } from "@/lib/types";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { StatusLed } from "@/components/ui/StatusLed";
import { cn, formatClock, formatDuration } from "@/lib/format";

interface ScanHistoryProps {
  entries: ScanEntry[];
  selectedId: string;
  onSelect: (id: string) => void;
  onEnqueue?: () => void;
}

export function ScanHistory({ entries, selectedId, onSelect }: ScanHistoryProps) {
  return (
    <section className="panel">
      <div className="border-b border-edge px-4 py-3">
        <MonoEyebrow index="04">Scan history · {String(entries.length).padStart(2, "0")}</MonoEyebrow>
      </div>
      <ol className="relative px-4 py-3">
        <span
          className="absolute left-[23px] top-4 bottom-4 w-px bg-edge"
          aria-hidden
        />
        {entries.map((e) => {
          const active = e.id === selectedId;
          const pending = e.status === "queued" || e.status === "scanning";
          return (
            <li key={e.id} className="relative pb-4 last:pb-0">
              <button
                type="button"
                onClick={() => onSelect(e.id)}
                className={cn(
                  "flex w-full items-start gap-3 rounded-sm border px-3 py-2.5 text-left transition-colors",
                  active
                    ? "border-live/40 bg-slate-hi"
                    : "border-transparent hover:border-edge hover:bg-slate-hi/60",
                  pending && "slide-in",
                )}
              >
                <StatusLed posture={e.posture} />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-data text-[12px] text-text">
                      {formatClock(e.at)}
                    </span>
                    <span className="font-data text-[11px] uppercase tracking-wider text-text-faint">
                      {e.trigger}
                    </span>
                    {pending ? (
                      <span className="font-data text-[11px] uppercase tracking-wider text-live">
                        {e.status}
                      </span>
                    ) : null}
                  </div>
                  <p className="mt-1 font-data text-[12px] text-text-dim">
                    drift {e.driftPct.toFixed(1)}% · {formatDuration(e.durationMs)}
                  </p>
                </div>
              </button>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
