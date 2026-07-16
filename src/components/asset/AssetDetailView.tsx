"use client";

import { useMemo, useState } from "react";
import { AppShell } from "@/components/shell/AppShell";
import { DiffViewer } from "@/components/asset/DiffViewer";
import { FindingsList } from "@/components/asset/FindingsList";
import { ScanHistory } from "@/components/asset/ScanHistory";
import { VerdictPanel } from "@/components/asset/VerdictPanel";
import { Button } from "@/components/ui/Button";
import { StatusPill } from "@/components/ui/StatusPill";
import { useToast } from "@/components/ui/Toast";
import {
  aiVerdict,
  changeRegions,
  findings,
  getAsset,
  globalPosture,
  scanHistory,
  assets,
} from "@/lib/fixtures";
import type { ScanEntry } from "@/lib/types";
import { cn } from "@/lib/format";

interface AssetDetailProps {
  id: string;
}

export function AssetDetailView({ id }: AssetDetailProps) {
  const asset = getAsset(id);
  const { push } = useToast();
  const initial = useMemo(
    () => (asset ? (scanHistory[asset.id] ?? scanHistory.a1 ?? []) : []),
    [asset],
  );
  const [history, setHistory] = useState<ScanEntry[]>(initial);
  const [selectedId, setSelectedId] = useState(initial[0]?.id ?? "");

  if (!asset) {
    return (
      <AppShell crumbs={[{ label: "ASSETS", href: "/assets" }, { label: "NOT FOUND" }]} posture="watch" watchCount={0}>
        <p className="font-data text-critical">ASSET NOT FOUND</p>
      </AppShell>
    );
  }

  const posture = globalPosture(assets);
  const watchCount = assets.filter(
    (a) => a.posture === "watch" || a.posture === "critical",
  ).length;

  const verdictTone =
    asset.posture === "critical"
      ? "critical"
      : asset.posture === "watch"
        ? "watch"
        : "secure";

  const verdictLabel =
    asset.posture === "critical"
      ? "DEFACEMENT"
      : asset.posture === "watch"
        ? "DRIFT DETECTED"
        : "BASELINE HELD";

  const showAi = asset.posture !== "secure";

  return (
    <AppShell
      crumbs={[
        { label: "ASSETS", href: "/assets" },
        { label: asset.name.toUpperCase() },
      ]}
      posture={posture}
      watchCount={watchCount}
    >
      <div className="mb-5 flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="type-label">Asset · datum</p>
          <h1
            className={cn(
              "mt-2 type-display",
              verdictTone === "critical"
                ? "text-critical"
                : verdictTone === "watch"
                  ? "text-watch"
                  : "text-secure",
            )}
          >
            {verdictLabel}
          </h1>
          <p className="mt-2 flex flex-wrap items-baseline gap-3">
            <span className="font-display type-data-lg text-text">
              {asset.driftScore.toFixed(1)}%
            </span>
            <span className="type-small text-text-dim">
              {showAi ? aiVerdict.summary : "Live capture within baseline tolerance."}
            </span>
          </p>
          <p className="mt-2 font-data text-[12px] text-text-faint">{asset.host}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <StatusPill tone={verdictTone}>{asset.posture.toUpperCase()}</StatusPill>
          <Button
            onClick={() => {
              const row: ScanEntry = {
                id: `q-${Date.now()}`,
                at: new Date().toISOString(),
                driftPct: asset.driftScore,
                posture: "scanning",
                trigger: "MANUAL",
                durationMs: 0,
                status: "queued",
              };
              setHistory((prev) => [row, ...prev]);
              setSelectedId(row.id);
              push(`SCAN QUEUED · ${asset.name}`);
              window.setTimeout(() => {
                setHistory((prev) =>
                  prev.map((e) =>
                    e.id === row.id ? { ...e, status: "scanning" as const } : e,
                  ),
                );
              }, 900);
              window.setTimeout(() => {
                setHistory((prev) =>
                  prev.map((e) =>
                    e.id === row.id
                      ? {
                          ...e,
                          status: "done",
                          posture: asset.posture,
                          durationMs: 3800,
                        }
                      : e,
                  ),
                );
                push(`SCAN DONE · ${asset.name}`);
              }, 2800);
            }}
          >
            Scan now
          </Button>
          <Button
            variant="secondary"
            onClick={() => push(`RE-BASELINE · ${asset.name} · audit row written`)}
          >
            Re-baseline
          </Button>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.55fr_0.85fr]">
        <div className="flex flex-col gap-4">
          <DiffViewer
            baselineSrc={asset.baselineCapture}
            currentSrc={asset.currentCapture}
            driftPct={asset.driftScore}
            regions={changeRegions}
          />
          <ScanHistory
            entries={history}
            selectedId={selectedId}
            onSelect={setSelectedId}
          />
        </div>
        <div className="flex flex-col gap-4">
          <VerdictPanel verdict={showAi ? aiVerdict : null} />
          <FindingsList findings={findings} />
        </div>
      </div>
    </AppShell>
  );
}
