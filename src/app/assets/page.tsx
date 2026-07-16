"use client";

import Link from "next/link";
import { AppShell } from "@/components/shell/AppShell";
import { Button } from "@/components/ui/Button";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { StatusLed } from "@/components/ui/StatusLed";
import { assets, globalPosture } from "@/lib/fixtures";
import { RelativeTime } from "@/components/ui/RelativeTime";
import { useState } from "react";
import { AddAssetDrawer } from "@/components/assets/AddAssetDrawer";
import { useToast } from "@/components/ui/Toast";
import type { Asset } from "@/lib/types";

export default function AssetsPage() {
  const [list, setList] = useState<Asset[]>(assets);
  const [open, setOpen] = useState(false);
  const { push } = useToast();
  const posture = globalPosture(list);
  const watchCount = list.filter(
    (a) => a.posture === "watch" || a.posture === "critical",
  ).length;

  return (
    <AppShell
      crumbs={[{ label: "ASSETS" }]}
      posture={posture}
      watchCount={watchCount}
    >
      <div className="mb-5 flex items-end justify-between gap-3">
        <div>
          <MonoEyebrow index="07">Asset register · {String(list.length).padStart(2, "0")}</MonoEyebrow>
          <h1 className="mt-2 type-h1 text-text">Assets under watch</h1>
        </div>
        <Button onClick={() => setOpen(true)}>+ Establish baseline</Button>
      </div>

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
            {list.map((a) => (
              <tr
                key={a.id}
                className="h-[38px] border-b border-edge last:border-0 hover:bg-slate-hi"
              >
                <td className="px-4">
                  <StatusLed posture={a.posture} label />
                </td>
                <td className="px-4">
                  <Link
                    href={`/assets/${a.id}`}
                    className="text-[14px] text-text hover:underline"
                  >
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

      <AddAssetDrawer
        open={open}
        onClose={() => setOpen(false)}
        onCreated={(asset) => {
          setList((prev) => [asset, ...prev]);
          push(`BASELINE JOB · ${asset.name} queued`);
        }}
      />
    </AppShell>
  );
}
