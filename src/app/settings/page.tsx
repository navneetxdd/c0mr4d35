"use client";

import { AppShell } from "@/components/shell/AppShell";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { assets, BUILD_HASH, globalPosture } from "@/lib/fixtures";

export default function SettingsPage() {
  const posture = globalPosture(assets);
  const watchCount = assets.filter(
    (a) => a.posture === "watch" || a.posture === "critical",
  ).length;

  return (
    <AppShell crumbs={[{ label: "SETTINGS" }]} posture={posture} watchCount={watchCount}>
      <MonoEyebrow index="16">Workspace</MonoEyebrow>
      <h1 className="mt-2 type-h1 text-text">Settings</h1>
      <div className="panel mt-6 divide-y divide-edge">
        <Row label="Org" value="acme-ops" />
        <Row label="Theme" value="DARK · NOC (locked)" />
        <Row label="Worker" value="wrk-render-01 · sequential queue" />
        <Row label="Build" value={BUILD_HASH} />
        <Row label="Alert channel" value="Discord webhook · configured" />
      </div>
    </AppShell>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 px-4 py-3">
      <span className="type-label">{label}</span>
      <span className="font-data text-[13px] text-text-dim">{value}</span>
    </div>
  );
}
