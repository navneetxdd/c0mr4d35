"use client";

import { useMemo } from "react";
import { cn } from "@/lib/format";

/**
 * Decorative atmosphere for the login stage — intentionally NOT live telemetry.
 * Copy is framed as aesthetic glyph noise so judges don't confuse it with product data.
 */
const ATMOSPHERE = [
  "INTEGRITY · waiting for session",
  "BASELINE  · hash lattice idle",
  "DRIFT     · observer offline",
  "AUDIT     · chain sealed",
  "POSTURE   · —",
  "EVIDENCE  · buffer empty",
  "INTEGRITY · waiting for session",
  "BASELINE  · hash lattice idle",
  "DRIFT     · observer offline",
  "AUDIT     · chain sealed",
  "POSTURE   · —",
  "EVIDENCE  · buffer empty",
  "INTEGRITY · waiting for session",
  "BASELINE  · hash lattice idle",
  "DRIFT     · observer offline",
  "AUDIT     · chain sealed",
  "POSTURE   · —",
  "EVIDENCE  · buffer empty",
  "INTEGRITY · waiting for session",
  "BASELINE  · hash lattice idle",
  "DRIFT     · observer offline",
];

export function TerminalLogs({ className, side = "left" }: { className?: string; side?: "left" | "right" }) {
  const blocks = useMemo(() => {
    return Array.from({ length: 15 }).map((_, i) => (
      <div key={i} className="mb-4">
        {ATMOSPHERE.map((log, j) => (
          <div key={j} className="flex gap-2">
            <span className="opacity-50">
              30{i}
              {j} |
            </span>
            <span>{log}</span>
          </div>
        ))}
      </div>
    ));
  }, []);

  return (
    <div
      className={cn(
        "pointer-events-none absolute inset-y-0 w-64 overflow-hidden font-data text-[10px] uppercase leading-relaxed text-live/60 crt-flicker",
        side === "left" ? "left-4 text-left" : "right-4 text-right",
        className,
      )}
      aria-hidden
      style={{
        maskImage: "linear-gradient(to bottom, transparent, black 10%, black 90%, transparent)",
        WebkitMaskImage: "linear-gradient(to bottom, transparent, black 10%, black 90%, transparent)",
      }}
    >
      <div className="mt-2 h-[200%] w-full animate-terminal-scroll">{blocks}</div>
    </div>
  );
}
