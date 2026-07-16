"use client";

import { useState } from "react";
import type { Finding, FindingGroup } from "@/lib/types";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { StatusPill } from "@/components/ui/StatusPill";
import { severityTone } from "@/lib/format";
import { cn } from "@/lib/format";

const GROUP_ORDER: FindingGroup[] = [
  "DEFACEMENT",
  "BEHAVIOR",
  "PORTS",
  "SUBDOMAINS",
  "HEADERS",
  "COOKIES",
  "CORS",
  "CONTENT",
  "METHODS",
  "TLS",
  "DNS",
  "EXPOSED PATHS",
  "CVE",
];

interface FindingsListProps {
  findings: Finding[];
}

export function FindingsList({ findings }: FindingsListProps) {
  const [openId, setOpenId] = useState<string | null>(findings[0]?.id ?? null);

  return (
    <section className="panel">
      <div className="border-b border-edge px-4 py-3">
        <MonoEyebrow index="06">
          Findings · {String(findings.length).padStart(2, "0")}
        </MonoEyebrow>
      </div>
      <div className="divide-y divide-edge">
        {GROUP_ORDER.map((group) => {
          const rows = findings.filter((f) => f.group === group);
          if (!rows.length) return null;
          return (
            <div key={group} className="px-4 py-3">
              <p className="type-label mb-2">{group}</p>
              <ul className="space-y-2">
                {rows.map((f) => {
                  const expanded = openId === f.id;
                  return (
                    <li key={f.id} className="rounded-sm border border-edge bg-void/40">
                      <button
                        type="button"
                        className="flex w-full items-start gap-2 px-3 py-2.5 text-left hover:bg-slate-hi/50"
                        onClick={() => setOpenId(expanded ? null : f.id)}
                        aria-expanded={expanded}
                      >
                        <StatusPill tone={severityTone(f.severity)}>{f.severity}</StatusPill>
                        <span className="min-w-0 flex-1 font-data text-[12px] text-text">
                          {f.title}
                          {f.cveId ? (
                            <span className="mt-1 block text-scan underline-offset-2">
                              {f.stackFamily} · {f.cveId}
                            </span>
                          ) : null}
                        </span>
                        <span className="font-data text-[10px] text-text-faint">
                          {expanded ? "−" : "+"}
                        </span>
                      </button>
                      {expanded ? (
                        <div className="border-t border-edge px-3 py-2">
                          <p className="type-small text-text-dim">{f.detail}</p>
                          {f.observedUrl ? (
                            <p className="mt-1 font-data text-[11px] text-text-faint">
                              OBSERVED ON · {f.observedUrl}
                            </p>
                          ) : null}
                          {f.evidence ? (
                            <p className="mt-1 font-data text-[11px] text-text-faint">
                              EVIDENCE · {f.evidence}
                            </p>
                          ) : null}
                          <p className={cn("mt-2 type-data-sm text-text-faint")}>
                            REMEDIATION · {f.remediation}
                          </p>
                        </div>
                      ) : null}
                    </li>
                  );
                })}
              </ul>
            </div>
          );
        })}
      </div>
    </section>
  );
}
