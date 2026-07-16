"use client";

import type { Telemetry } from "@/lib/types";

interface TelemetryTickerProps {
  data: Telemetry;
}

export function TelemetryTicker({ data }: TelemetryTickerProps) {
  const items = [
    `ASSETS ${String(data.assets).padStart(2, "0")}`,
    `SCANS/24H ${data.scans24h}`,
    `OPEN INCIDENTS ${String(data.openIncidents).padStart(2, "0")}`,
    `MTTD ${data.mttdSec != null ? `${data.mttdSec}s` : "—"}`,
    `SCAN OK/24H ${data.scanSuccessPct != null ? `${data.scanSuccessPct.toFixed(1)}%` : "—"}`,
  ];

  return (
    <div className="flex h-7 items-center overflow-x-auto scroll-thin border-b border-edge bg-carbon px-3">
      <div className="flex min-w-max items-center gap-0 font-data text-[11px] tracking-[0.06em] text-text-dim">
        {items.map((item, i) => (
          <span key={item} className="flex items-center">
            {i > 0 ? <span className="mx-3 text-text-faint">│</span> : null}
            <span>{item}</span>
          </span>
        ))}
      </div>
    </div>
  );
}
