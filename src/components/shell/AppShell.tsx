"use client";

import { Rail } from "@/components/shell/Rail";
import { TelemetryTicker } from "@/components/shell/TelemetryTicker";
import { Topbar } from "@/components/shell/Topbar";
import { telemetry } from "@/lib/fixtures";

interface AppShellProps {
  children: React.ReactNode;
  crumbs: { label: string; href?: string }[];
  posture: "secure" | "watch" | "critical";
  watchCount: number;
  onScanAll?: () => void;
}

export function AppShell({
  children,
  crumbs,
  posture,
  watchCount,
  onScanAll,
}: AppShellProps) {
  return (
    <div className="flex min-h-[100dvh] flex-col bg-void text-text">
      <TelemetryTicker data={telemetry} />
      <div className="flex min-h-0 flex-1">
        <Rail isAdmin />
        <div className="flex min-w-0 flex-1 flex-col pb-14 md:pb-0">
          <Topbar
            crumbs={crumbs}
            posture={posture}
            watchCount={watchCount}
            onScanAll={onScanAll}
          />
          <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-6 sm:px-6 lg:px-8">
            {children}
          </main>
        </div>
      </div>
    </div>
  );
}
