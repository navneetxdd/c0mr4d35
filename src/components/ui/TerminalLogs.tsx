"use client";

import { useMemo } from "react";
import { cn } from "@/lib/format";

const FAKE_LOGS = [
  "RCE       Recur1-CorD002: active",
  "RCE       Recur1-CorD003: active",
  "RCE       Recur1-CorD004: active",
  "RCE       SQLi A011j",
  "DATAIN    CorD001-Routine: offline",
  "DATAIN    Sever1-Routine: active",
  "RCE       ",
  "DATAIN    CorD002",
  "RCE       Recur1-CorD005: active",
  "RCE       Recur1-CorD006: active",
  "RCE       Recur1-CorD007: active",
  "RCE       Recur1-CorD008: active",
  "DATAIN    Sever2-Routine: offline",
  "RCENG     MrtD",
  "RCE       Recur1-CorD009: active",
  "RCE       Recur1-CorD010: active",
  "RCE       Recur1-CorD011: active",
  "RCE       Recur1-CorD012: active",
  "DATAIN    Sever3-Routine: active",
  "RCENG     MrtD",
  "RCE       Recur1-CorD013: active",
];

export function TerminalLogs({ className, side = "left" }: { className?: string; side?: "left" | "right" }) {
  const blocks = useMemo(() => {
    // Generate a long list to scroll infinitely
    return Array.from({ length: 15 }).map((_, i) => (
      <div key={i} className="mb-4">
        {FAKE_LOGS.map((log, j) => (
          <div key={j} className="flex gap-2">
            <span className="opacity-50">30{i}{j} |</span>
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
        className
      )}
      style={{
        maskImage: "linear-gradient(to bottom, transparent, black 10%, black 90%, transparent)",
        WebkitMaskImage: "linear-gradient(to bottom, transparent, black 10%, black 90%, transparent)",
      }}
    >
      <div className="absolute top-4 border-b border-live/30 pb-1 mb-2">
        <span className="bg-live text-void px-1 font-bold">
          VULNERABILITY ASSESSMENT
        </span>
      </div>
      <div className="mt-12 h-[200%] w-full animate-terminal-scroll">
        {blocks}
      </div>
    </div>
  );
}
