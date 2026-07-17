"use client";

import React from "react";
import { cn } from "@/lib/format";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";

interface ScriptSignal {
  src: string | null;
  sha256: string;
}

interface Finding {
  id: string;
  category: string;
  risk: string;
  title: string;
  detail: string;
  remediation: string;
  evidence?: string | null;
}

interface SupplyChainPanelProps {
  scripts: ScriptSignal[];
  egress: string[];
  findings: Finding[];
}

export function SupplyChainPanel({ scripts, egress, findings }: SupplyChainPanelProps) {
  // Extract integrity findings
  const integrityFindings = findings.filter(
    (f) => f.category === "SUPPLY_CHAIN"
  );

  const newScriptSrcs = new Set(
    integrityFindings
      .filter((f) => f.id.startsWith("integrity-new-script-"))
      .map((f) => f.evidence?.match(/src=([^\s]+)/)?.[1] ?? "")
      .filter(Boolean)
  );

  const modifiedScriptSrcs = new Set(
    integrityFindings
      .filter((f) => f.id.startsWith("integrity-modified-script-"))
      .map((f) => f.evidence?.match(/src=([^\s]+)/)?.[1] ?? "")
      .filter(Boolean)
  );

  const newInlineHashes = new Set(
    integrityFindings
      .filter((f) => f.id.startsWith("integrity-new-inline-"))
      .map((f) => f.evidence?.match(/sha256=([^\s]+)/)?.[1] ?? "")
      .filter(Boolean)
  );

  const newEgressDomains = new Set(
    integrityFindings
      .filter((f) => f.id.startsWith("integrity-new-egress-"))
      .map((f) => f.evidence?.match(/domain=([^\s]+)/)?.[1] ?? "")
      .filter(Boolean)
  );

  const hasAlerts = integrityFindings.length > 0;

  return (
    <section className={cn("panel relative p-4 stagger-in", hasAlerts && "glow-critical border-critical/30")}>
      <RegistrationMarks />
      <div className="flex items-center justify-between border-b border-edge pb-3">
        <div className="flex items-center gap-2">
          <span className={cn("h-1.5 w-1.5 rounded-full", hasAlerts ? "bg-critical led-critical" : "bg-secure")} />
          <span className="font-display text-[14px] font-bold uppercase tracking-wider text-text">
            03 · Supply Chain & Outbound Egress Integrity
          </span>
        </div>
        {hasAlerts && (
          <span className="rounded-sm bg-critical/10 px-2 py-0.5 font-data text-[10px] font-bold text-critical uppercase tracking-wider border border-critical/30">
            INTEGRITY ALERT DETECTED
          </span>
        )}
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-[1.4fr_0.6fr]">
        {/* Scripts Inventory */}
        <div className="overflow-auto rounded-sm border border-edge bg-void/10">
          <p className="border-b border-edge px-3 py-2 type-label">Script Inventory ({scripts.length})</p>
          {scripts.length ? (
            <table className="w-full text-left font-data text-[11px]">
              <thead className="text-text-faint">
                <tr>
                  <th className="px-3 py-1.5">SOURCE</th>
                  <th className="px-3 py-1.5">SHA-256 HASH</th>
                  <th className="px-3 py-1.5">STATUS</th>
                </tr>
              </thead>
              <tbody>
                {scripts.map((s, idx) => {
                  const isInline = s.src === null;
                  const displayName = isInline ? "[INLINE SCRIPT BLOCK]" : s.src!;
                  
                  let status = "LEGITIMATE";
                  let isAlert = false;
                  let isNew = false;

                  if (s.src) {
                    if (newScriptSrcs.has(s.src)) {
                      status = "NEW SOURCE (UNAUTHORIZED)";
                      isAlert = true;
                      isNew = true;
                    } else if (modifiedScriptSrcs.has(s.src)) {
                      status = "MODIFIED (HASH MISMATCH)";
                      isAlert = true;
                    }
                  } else {
                    if (newInlineHashes.has(s.sha256)) {
                      status = "NEW INLINE BLOCK (UNAUTHORIZED)";
                      isAlert = true;
                      isNew = true;
                    }
                  }

                  return (
                    <tr
                      key={idx}
                      className={cn(
                        "border-t border-edge hover:bg-void/40",
                        isAlert && (isNew ? "bg-critical/5" : "bg-watch/5")
                      )}
                    >
                      <td
                        className={cn(
                          "px-3 py-2 truncate max-w-[240px]",
                          isInline ? "text-text-faint italic" : "text-text font-medium",
                          isAlert && (isNew ? "text-critical" : "text-watch")
                        )}
                        title={displayName}
                      >
                        {displayName}
                      </td>
                      <td className="px-3 py-2 text-text-faint font-mono">
                        {s.sha256.slice(0, 16)}...
                      </td>
                      <td className="px-3 py-2">
                        <span
                          className={cn(
                            "font-data text-[10px] font-bold px-1.5 py-0.5 rounded-sm",
                            isAlert
                              ? isNew
                                ? "bg-critical/10 text-critical border border-critical/30"
                                : "bg-watch/10 text-watch border border-watch/30"
                              : "bg-secure/10 text-secure"
                          )}
                        >
                          {status}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            <p className="px-3 py-4 font-data text-[11px] text-text-faint">No scripts detected in document.</p>
          )}
        </div>

        {/* Outbound Egress Domains */}
        <div className="overflow-auto rounded-sm border border-edge bg-void/10 flex flex-col">
          <p className="border-b border-edge px-3 py-2 type-label">Outbound Egress Domains ({egress.length})</p>
          {egress.length ? (
            <div className="flex-1 divide-y divide-edge">
              {egress.map((domain, idx) => {
                const isNew = newEgressDomains.has(domain);
                return (
                  <div
                    key={idx}
                    className={cn(
                      "px-3 py-2 flex items-center justify-between font-data text-[11px]",
                      isNew ? "bg-critical/5" : "hover:bg-void/40"
                    )}
                  >
                    <span className={cn(isNew ? "text-critical font-bold" : "text-text")}>
                      {domain}
                    </span>
                    {isNew ? (
                      <span className="font-data text-[9px] font-bold text-critical bg-critical/10 px-1 py-0.5 border border-critical/30 rounded-sm blink">
                        SUSPECTED EXFIL
                      </span>
                    ) : (
                      <span className="text-text-faint text-[10px]">AUTHORIZED</span>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <p className="px-3 py-4 font-data text-[11px] text-text-faint flex-1 flex items-center justify-center">
              No outbound egress domains found.
            </p>
          )}
        </div>
      </div>
    </section>
  );
}
