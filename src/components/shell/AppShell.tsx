"use client";

import { Rail } from "@/components/shell/Rail";
import { TelemetryTicker } from "@/components/shell/TelemetryTicker";
import { Topbar } from "@/components/shell/Topbar";
import type { ShellContext } from "@/lib/data/shell";

interface AppShellProps {
  children: React.ReactNode;
  crumbs: { label: string; href?: string }[];
  shell: ShellContext;
  onScanAll?: () => void | Promise<void>;
}

/**
 * Dashboard shell — ports the UI-branch NOC grid look without mounting
 * WebGL on every authenticated page (that tanked CPU/GPU on Overview/Scan).
 */
export function AppShell({ children, crumbs, shell, onScanAll }: AppShellProps) {
  return (
    <div className="relative flex min-h-[100dvh] flex-col bg-void bg-grid text-text">
      <div
        className="pointer-events-none absolute inset-0 z-0 bg-[radial-gradient(ellipse_at_top,rgba(184,240,76,0.06),transparent_55%)]"
        aria-hidden
      />
      <div className="relative z-10 w-full">
        <TelemetryTicker data={shell.telemetry} />
      </div>
      <div className="relative z-10 flex min-h-0 flex-1">
        <Rail isAdmin={shell.isAdmin} />
        <div className="flex min-w-0 flex-1 flex-col pb-14 md:pb-0">
          <Topbar
            crumbs={crumbs}
            posture={shell.posture}
            watchCount={shell.watchCount}
            profile={shell.profile}
            isAnalyst={shell.isAnalyst}
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
