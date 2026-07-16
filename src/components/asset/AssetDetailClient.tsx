"use client";

import { useRouter } from "next/navigation";
import Link from "next/link";
import { useState } from "react";
import { AppShell } from "@/components/shell/AppShell";
import { DomDriftPanel } from "@/components/asset/DomDriftPanel";
import { FindingsList } from "@/components/asset/FindingsList";
import { ScanHistory } from "@/components/asset/ScanHistory";
import { AssetVerdictPanel } from "@/components/asset/AssetVerdictPanel";
import { Button } from "@/components/ui/Button";
import { StatusPill } from "@/components/ui/StatusPill";
import { useToast } from "@/components/ui/Toast";
import { rebaselineAsset, triggerAssetScan } from "@/app/actions/datum";
import type { ShellContext } from "@/lib/data/shell";
import type { Asset, Finding, ScanEntry } from "@/lib/types";
import type { AiVerdict } from "@/lib/ai/gemini";
import { cn } from "@/lib/format";

interface AssetDetailClientProps {
  shell: ShellContext;
  assetView: Asset;
  scans: ScanEntry[];
  findings: Finding[];
  baselineHtml: string | null;
  aiVerdict: AiVerdict | null;
  isAnalyst: boolean;
}

export function AssetDetailClient({
  shell,
  assetView,
  scans,
  findings,
  baselineHtml,
  aiVerdict,
  isAnalyst,
}: AssetDetailClientProps) {
  const [history, setHistory] = useState(scans);
  const [selectedId, setSelectedId] = useState(scans[0]?.id ?? "");
  const [busy, setBusy] = useState(false);
  const { push } = useToast();
  const router = useRouter();

  const verdictTone =
    assetView.posture === "critical"
      ? "critical"
      : assetView.posture === "watch"
        ? "watch"
        : "secure";

  const verdictLabel =
    assetView.posture === "critical"
      ? "DEFACEMENT"
      : assetView.posture === "watch"
        ? "DRIFT DETECTED"
        : "BASELINE HELD";

  const showAi = assetView.posture !== "secure" || Boolean(aiVerdict?.available);

  async function handleScan() {
    if (!isAnalyst || busy) return;
    setBusy(true);
    const row: ScanEntry = {
      id: `pending-${Date.now()}`,
      at: new Date().toISOString(),
      driftPct: assetView.driftScore,
      posture: "scanning",
      trigger: "MANUAL",
      durationMs: 0,
      status: "scanning",
    };
    setHistory((prev) => [row, ...prev]);
    setSelectedId(row.id);
    push(`SCAN STARTED · ${assetView.name}`);

    const result = await triggerAssetScan(assetView.id);
    setBusy(false);
    if (!result.ok) {
      push(`SCAN FAILED · ${result.error}`);
      return;
    }
    router.refresh();
    push(`SCAN DONE · ${assetView.name}`);
  }

  async function handleRebaseline() {
    if (!isAnalyst || busy) return;
    setBusy(true);
    push(`RE-BASELINE · ${assetView.name}`);
    const result = await rebaselineAsset(assetView.id);
    setBusy(false);
    if (!result.ok) {
      push(`RE-BASELINE FAILED · ${result.error}`);
      return;
    }
    router.refresh();
    push(`BASELINE UPDATED · ${assetView.name}`);
  }

  return (
    <AppShell
      crumbs={[
        { label: "ASSETS", href: "/assets" },
        { label: assetView.name.toUpperCase() },
      ]}
      shell={shell}
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
              {assetView.driftScore.toFixed(1)}%
            </span>
            <span className="type-small text-text-dim">
              {aiVerdict?.available
                ? aiVerdict.summary
                : "DOM hash comparison against stored baseline."}
            </span>
          </p>
          <p className="mt-2 font-data text-[12px] text-text-faint">{assetView.host}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <StatusPill tone={verdictTone}>{assetView.posture.toUpperCase()}</StatusPill>
          {isAnalyst ? (
            <>
              <Button onClick={handleScan} disabled={busy}>
                {busy ? "Scanning…" : "Scan now"}
              </Button>
              <Button variant="secondary" onClick={handleRebaseline} disabled={busy}>
                Re-baseline
              </Button>
            </>
          ) : null}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.55fr_0.85fr]">
        <div className="flex flex-col gap-4">
          <DomDriftPanel driftPct={assetView.driftScore} baselineHtml={baselineHtml} />
          <ScanHistory entries={history} selectedId={selectedId} onSelect={setSelectedId} />
        </div>
        <div className="flex flex-col gap-4">
          <AssetVerdictPanel verdict={showAi ? aiVerdict : null} />
          <FindingsList findings={findings} />
        </div>
      </div>
    </AppShell>
  );
}

export function AssetNotFound({ shell }: { shell: ShellContext }) {
  return (
    <AppShell crumbs={[{ label: "ASSETS", href: "/assets" }, { label: "NOT FOUND" }]} shell={shell}>
      <p className="font-data text-critical">ASSET NOT FOUND</p>
      <Link href="/assets" className="mt-4 inline-block font-data text-[12px] text-scan hover:underline">
        ← Back to assets
      </Link>
    </AppShell>
  );
}
