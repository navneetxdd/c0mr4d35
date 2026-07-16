"use client";

import { useState } from "react";
import { AppShell } from "@/components/shell/AppShell";
import { Button } from "@/components/ui/Button";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";
import { verifyAuditChain } from "@/app/actions/datum";
import type { ShellContext } from "@/lib/data/shell";
import type { AuditEntry } from "@/lib/types";
import { formatClock } from "@/lib/format";

interface AuditClientProps {
  shell: ShellContext;
  entries: AuditEntry[];
}

export function AuditClient({ shell, entries: initial }: AuditClientProps) {
  const [result, setResult] = useState<string | null>(null);
  const [ok, setOk] = useState<boolean | null>(null);
  const entries = initial;

  return (
    <AppShell crumbs={[{ label: "AUDIT" }]} shell={shell}>
      <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
        <div>
          <MonoEyebrow index="14">Tamper-evident ledger</MonoEyebrow>
          <h1 className="mt-2 type-h1 text-text">Audit log</h1>
          <p className="mt-2 type-small text-text-dim">
            Append-only. Hash chain verified server-side against Supabase.
          </p>
        </div>
        {shell.isAdmin ? (
          <Button
            variant="secondary"
            onClick={async () => {
              const res = await verifyAuditChain();
              setOk(res.ok);
              setResult(res.message);
            }}
          >
            Verify chain
          </Button>
        ) : null}
      </div>

      {result ? (
        <div
          className={`panel relative mb-4 px-4 py-3 font-data text-[12px] ${
            ok ? "text-live glow-live" : "text-critical glow-critical"
          }`}
        >
          <RegistrationMarks />
          {result}
        </div>
      ) : null}

      {entries.length === 0 ? (
        <div className="panel px-6 py-16 text-center font-data text-[12px] text-text-faint">
          No audit entries yet — mutations will append to the chain automatically.
        </div>
      ) : (
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
              {entries.map((e) => (
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
      )}
    </AppShell>
  );
}
