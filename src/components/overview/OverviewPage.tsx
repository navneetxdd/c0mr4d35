"use client";

import { useMemo, useState } from "react";
import { AppShell } from "@/components/shell/AppShell";
import { AssetTile } from "@/components/overview/AssetTile";
import { EmptyAssets } from "@/components/overview/EmptyAssets";
import { EventFeed } from "@/components/overview/EventFeed";
import { GlobalPosture } from "@/components/overview/GlobalPosture";
import { MetricsStrip } from "@/components/overview/MetricsStrip";
import { AddAssetDrawer } from "@/components/assets/AddAssetDrawer";
import { assets as seedAssets, feedEvents, globalPosture, telemetry } from "@/lib/fixtures";
import type { Asset } from "@/lib/types";
import { useToast } from "@/components/ui/Toast";

function OverviewInner() {
  const [list, setList] = useState<Asset[]>(seedAssets);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const { push } = useToast();

  const posture = useMemo(() => globalPosture(list), [list]);
  const watchCount = list.filter(
    (a) => a.posture === "watch" || a.posture === "critical",
  ).length;

  const promoted = list.find((a) => a.openIncident && a.posture === "critical");
  const rest = list.filter((a) => a.id !== promoted?.id);

  if (list.length === 0) {
    return (
      <>
        <EmptyAssets onEstablish={() => setDrawerOpen(true)} />
        <AddAssetDrawer
          open={drawerOpen}
          onClose={() => setDrawerOpen(false)}
          onCreated={(asset) => {
            setList((prev) => [asset, ...prev]);
            push(`BASELINE JOB · ${asset.name} queued`);
          }}
        />
      </>
    );
  }

  return (
    <>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.45fr)_minmax(280px,0.85fr)] lg:items-start">
        <div className="flex flex-col gap-4">
          <GlobalPosture assets={list} posture={posture} watchCount={watchCount} />
          <div className="grid gap-4 sm:grid-cols-2">
            {promoted ? <AssetTile asset={promoted} index={1} large /> : null}
            {rest.slice(0, promoted ? 2 : 4).map((a, i) => (
              <AssetTile key={a.id} asset={a} index={i + 2} />
            ))}
          </div>
          <div className="grid gap-4 sm:grid-cols-3">
            {rest.slice(promoted ? 2 : 4).map((a, i) => (
              <AssetTile key={a.id} asset={a} index={i + 6} />
            ))}
          </div>
          <MetricsStrip data={telemetry} />
        </div>
        <div className="lg:sticky lg:top-4 lg:self-start lg:max-h-[calc(100dvh-7rem)]">
          <EventFeed initial={feedEvents} />
        </div>
      </div>
      <AddAssetDrawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        onCreated={(asset) => {
          setList((prev) => [asset, ...prev]);
          push(`BASELINE JOB · ${asset.name} queued`);
        }}
      />
    </>
  );
}

export function OverviewPage() {
  const posture = globalPosture(seedAssets);
  const watchCount = seedAssets.filter(
    (a) => a.posture === "watch" || a.posture === "critical",
  ).length;

  return (
    <AppShell
      crumbs={[{ label: "COMMAND" }, { label: "OVERVIEW" }]}
      posture={posture}
      watchCount={watchCount}
      onScanAll={() => undefined}
    >
      <OverviewInner />
    </AppShell>
  );
}
