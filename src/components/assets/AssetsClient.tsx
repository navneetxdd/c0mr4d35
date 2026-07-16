"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { AppShell } from "@/components/shell/AppShell";
import { Button } from "@/components/ui/Button";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { StatusLed } from "@/components/ui/StatusLed";
import { RelativeTime } from "@/components/ui/RelativeTime";
import { AddAssetDrawer } from "@/components/assets/AddAssetDrawer";
import { scanAllAssetsAction } from "@/app/actions/datum";
import type { ShellContext } from "@/lib/data/shell";
import type { Asset } from "@/lib/types";
import { useToast } from "@/components/ui/Toast";

interface AssetsClientProps {
  shell: ShellContext;
  assets: Asset[];
}

export function AssetsClient({ shell, assets: initial }: AssetsClientProps) {
  const [open, setOpen] = useState(false);
  const { push } = useToast();
  const router = useRouter();

  async function handleScanAll() {
    const result = await scanAllAssetsAction();
    if (result.ok) {
      push(`SCAN ALL · ${result.count} assets`);
      router.refresh();
    }
  }

  return (
    <AppShell crumbs={[{ label: "ASSETS" }]} shell={shell} onScanAll={handleScanAll}>
      <div className="mb-5 flex items-end justify-between gap-3">
        <div>
          <MonoEyebrow index="07">Asset register · {String(initial.length).padStart(2, "0")}</MonoEyebrow>
          <h1 className="mt-2 type-h1 text-text">Assets under watch</h1>
        </div>
        {shell.isAnalyst ? (
          <Button onClick={() => setOpen(true)}>+ Establish baseline</Button>
        ) : null}
      </div>

      {initial.length === 0 ? (
        <div className="panel px-6 py-16 text-center">
          <p className="type-h2 text-text-dim">No assets monitored yet</p>
          <p className="mt-2 type-small text-text-faint">
            Add a public URL to establish a baseline and start continuous assessment.
          </p>
          {shell.isAnalyst ? (
            <Button className="mt-6" onClick={() => setOpen(true)}>
              Establish baseline
            </Button>
          ) : null}
        </div>
      ) : (
        <div className="panel overflow-hidden">
          <table className="w-full text-left">
            <thead className="sticky top-0 border-b border-edge bg-slate">
              <tr className="type-label">
                <th className="px-4 py-3 font-normal">Status</th>
                <th className="px-4 py-3 font-normal">Asset</th>
                <th className="px-4 py-3 font-normal">Host</th>
                <th className="px-4 py-3 font-normal">Drift</th>
                <th className="px-4 py-3 font-normal">Last check</th>
              </tr>
            </thead>
            <tbody>
              {initial.map((a) => (
                <tr
                  key={a.id}
                  className="h-[38px] border-b border-edge last:border-0 hover:bg-slate-hi"
                >
                  <td className="px-4">
                    <StatusLed posture={a.posture} label />
                  </td>
                  <td className="px-4">
                    <Link href={`/assets/${a.id}`} className="text-[14px] text-text hover:underline">
                      {a.name}
                    </Link>
                  </td>
                  <td className="px-4 font-data text-[12px] text-text-dim">{a.host}</td>
                  <td className="px-4 font-data text-[12px] text-text">
                    {a.driftScore.toFixed(1)}%
                  </td>
                  <td className="px-4 font-data text-[12px] text-text-faint">
                    <RelativeTime iso={a.lastCheckAt} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <AddAssetDrawer
        open={open}
        onClose={() => setOpen(false)}
        onCreated={() => {
          router.refresh();
          push("BASELINE ESTABLISHED");
        }}
      />
    </AppShell>
  );
}
