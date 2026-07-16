"use client";

import { useState } from "react";
import { AppShell } from "@/components/shell/AppShell";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";
import { useToast } from "@/components/ui/Toast";
import { assets, currentUser, globalPosture, members as seed } from "@/lib/fixtures";
import type { Member, Role } from "@/lib/types";
import { formatClock } from "@/lib/format";

export default function MembersPage() {
  const isAdmin = currentUser.role === "admin";
  const [rows, setRows] = useState<Member[]>(seed);
  const { push } = useToast();
  const posture = globalPosture(assets);
  const watchCount = assets.filter(
    (a) => a.posture === "watch" || a.posture === "critical",
  ).length;

  if (!isAdmin) {
    return (
      <AppShell crumbs={[{ label: "MEMBERS" }]} posture={posture} watchCount={watchCount}>
        <section className="panel relative mx-auto max-w-lg px-8 py-16 text-center">
          <RegistrationMarks />
          <MonoEyebrow index="99">Access control</MonoEyebrow>
          <h1 className="mt-4 type-h2 text-critical">INSUFFICIENT CLEARANCE</h1>
          <p className="mt-3 type-small text-text-dim">
            Member administration requires Admin role. This route is gated by RLS and
            server check — the UI mirrors that gate.
          </p>
        </section>
      </AppShell>
    );
  }

  return (
    <AppShell crumbs={[{ label: "MEMBERS" }]} posture={posture} watchCount={watchCount}>
      <div className="mb-5">
        <MonoEyebrow index="15">RBAC · org roster</MonoEyebrow>
        <h1 className="mt-2 type-h1 text-text">Members</h1>
      </div>

      <div className="panel overflow-hidden">
        <table className="w-full text-left">
          <thead className="border-b border-edge bg-slate">
            <tr className="type-label">
              <th className="px-4 py-3 font-normal">Email</th>
              <th className="px-4 py-3 font-normal">Role</th>
              <th className="px-4 py-3 font-normal">Joined</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((m) => (
              <tr
                key={m.id}
                className="h-[38px] border-b border-edge last:border-0 hover:bg-slate-hi"
              >
                <td className="px-4 font-data text-[13px] text-text">{m.email}</td>
                <td className="px-4">
                  <select
                    className="h-8 rounded-sm border border-edge bg-carbon px-2 font-data text-[12px] text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-live"
                    value={m.role}
                    onChange={(e) => {
                      const role = e.target.value as Role;
                      setRows((prev) =>
                        prev.map((r) => (r.id === m.id ? { ...r, role } : r)),
                      );
                      push(`ROLE CHANGE · ${m.email} → ${role} · audit written`);
                    }}
                    aria-label={`Role for ${m.email}`}
                  >
                    <option value="admin">Admin</option>
                    <option value="viewer">Viewer</option>
                  </select>
                </td>
                <td className="px-4 font-data text-[12px] text-text-faint">
                  {formatClock(m.joinedAt)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </AppShell>
  );
}
