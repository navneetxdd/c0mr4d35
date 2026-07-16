"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { AppShell } from "@/components/shell/AppShell";
import { AssetTile } from "@/components/overview/AssetTile";
import { EmptyAssets } from "@/components/overview/EmptyAssets";
import { EventFeed } from "@/components/overview/EventFeed";
import { GlobalPosture } from "@/components/overview/GlobalPosture";
import { MetricsStrip } from "@/components/overview/MetricsStrip";
import { AddAssetDrawer } from "@/components/assets/AddAssetDrawer";
import { scanAllAssetsAction } from "@/app/actions/datum";
import type { ShellContext } from "@/lib/data/shell";
import type { Asset, FeedEvent, Telemetry } from "@/lib/types";
import { useToast } from "@/components/ui/Toast";

interface OverviewClientProps {
  shell: ShellContext;
  assets: Asset[];
  telemetry: Telemetry;
  feed: FeedEvent[];
}

export function OverviewClient({ shell, assets: initial, telemetry, feed }: OverviewClientProps) {
  const [list, setList] = useState(initial);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const { push } = useToast();
  const router = useRouter();

  useEffect(() => {
    setList(initial);
  }, [initial]);

  const posture = useMemo(() => {
    if (list.some((a) => a.posture === "critical")) return "critical" as const;
    if (list.some((a) => a.posture === "watch" || a.posture === "scanning" || a.posture === "pending"))
      return "watch" as const;
    return "secure" as const;
  }, [list]);

  const watchCount = list.filter((a) => a.posture === "watch" || a.posture === "critical").length;
  const promoted = list.find((a) => a.openIncident && a.posture === "critical");
  const rest = list.filter((a) => a.id !== promoted?.id);

  async function handleScanAll() {
    const result = await scanAllAssetsAction();
    if (result.ok) {
      push(`SCAN ALL · ${result.count} assets queued`);
      router.refresh();
    }
  }

  return (
    <AppShell
      crumbs={[{ label: "COMMAND" }, { label: "OVERVIEW" }]}
      shell={{ ...shell, posture, watchCount, telemetry }}
      onScanAll={handleScanAll}
    >
      {list.length === 0 ? (
        <>
          <EmptyAssets onEstablish={() => setDrawerOpen(true)} />
          <AddAssetDrawer
            open={drawerOpen}
            onClose={() => setDrawerOpen(false)}
            onCreated={() => {
              router.refresh();
              push("BASELINE ESTABLISHED");
            }}
          />
        </>
      ) : (
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
              <EventFeed initial={feed} />
            </div>
          </div>
          <AddAssetDrawer
            open={drawerOpen}
            onClose={() => setDrawerOpen(false)}
            onCreated={() => {
              router.refresh();
              push("BASELINE ESTABLISHED");
            }}
          />
        </>
      )}
    </AppShell>
  );
}
