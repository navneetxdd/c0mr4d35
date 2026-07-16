"use client";

import { useMemo, useState } from "react";
import { AppShell } from "@/components/shell/AppShell";
import { Button } from "@/components/ui/Button";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";
import { assets, auditLog, globalPosture } from "@/lib/fixtures";
import { formatClock } from "@/lib/format";

export default function AuditPage() {
  const [result, setResult] = useState<string | null>(null);
  const posture = globalPosture(assets);
  const watchCount = assets.filter(
    (a) => a.posture === "watch" || a.posture === "critical",
  ).length;

  const chainOk = useMemo(() => {
    for (let i = 1; i < auditLog.length; i += 1) {
      const prev = auditLog[i - 1];
      const cur = auditLog[i];
      if (!prev || !cur) return false;
      if (cur.prevHash !== prev.thisHash) return false;
    }
    return true;
  }, []);

  return (
    <AppShell crumbs={[{ label: "AUDIT" }]} posture={posture} watchCount={watchCount}>
      <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
        <div>
          <MonoEyebrow index="14">Tamper-evident ledger</MonoEyebrow>
          <h1 className="mt-2 type-h1 text-text">Audit log</h1>
          <p className="mt-2 type-small text-text-dim">
            Append-only. Read-only for everyone including admin. Hash chain verified
            client-side.
          </p>
        </div>
        <Button
          variant="secondary"
          onClick={() => {
            setResult(
              chainOk
                ? `✓ CHAIN INTACT — ${auditLog.length.toLocaleString()} ENTRIES VERIFIED`
                : "✗ CHAIN BROKEN — DIVERGENCE AT LINK",
            );
          }}
        >
          Verify chain
        </Button>
      </div>

      {result ? (
        <div
          className={`panel relative mb-4 px-4 py-3 font-data text-[12px] ${
            chainOk ? "text-live glow-live" : "text-critical glow-critical"
          }`}
        >
          <RegistrationMarks />
          {result}
        </div>
      ) : null}

      <div className="panel overflow-x-auto">
        <table className="w-full min-w-[900px] text-left">
          <thead className="border-b border-edge bg-slate">
            <tr className="type-label">
              <th className="px-3 py-3 font-normal">Seq</th>
              <th className="px-3 py-3 font-normal">Timestamp</th>
              <th className="px-3 py-3 font-normal">Actor</th>
              <th className="px-3 py-3 font-normal">Action</th>
              <th className="px-3 py-3 font-normal">Target</th>
              <th className="px-3 py-3 font-normal">Prev → this</th>
            </tr>
          </thead>
          <tbody>
            {auditLog.map((e) => (
              <tr
                key={e.seq}
                className="h-[38px] border-b border-edge last:border-0 hover:bg-slate-hi"
              >
                <td className="px-3 font-data text-[12px] text-text">{e.seq}</td>
                <td className="px-3 font-data text-[12px] text-text-faint">
                  {formatClock(e.at)}
                </td>
                <td className="px-3 font-data text-[12px] text-text-dim">{e.actor}</td>
                <td className="px-3 font-data text-[12px] text-text">{e.action}</td>
                <td className="px-3 font-data text-[12px] text-text-dim">{e.target}</td>
                <td className="px-3 font-data text-[11px] text-text-faint">
                  {e.prevHash.slice(0, 8)}…{e.thisHash.slice(0, 8)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </AppShell>
  );
}
