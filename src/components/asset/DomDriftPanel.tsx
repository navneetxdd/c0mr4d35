import { RegistrationMarks } from "@/components/ui/RegistrationMarks";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { cn } from "@/lib/format";

interface DomDriftPanelProps {
  driftPct: number;
  baselineHtml: string | null;
}

export function DomDriftPanel({ driftPct, baselineHtml }: DomDriftPanelProps) {
  const tone =
    driftPct >= 25 ? "critical" : driftPct >= 8 ? "watch" : "secure";

  return (
    <section className="panel relative overflow-hidden">
      <RegistrationMarks />
      <div className="border-b border-edge px-4 py-3">
        <MonoEyebrow index="03">Baseline · DOM drift</MonoEyebrow>
      </div>
      <div className="p-4">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p
              className={cn(
                "type-h1",
                tone === "critical" ? "text-critical" : tone === "watch" ? "text-watch" : "text-secure",
              )}
            >
              {driftPct.toFixed(1)}%
            </p>
            <p className="mt-1 type-small text-text-dim">
              Content drift vs stored baseline HTML snapshot.
            </p>
          </div>
          <p className="font-data text-[11px] text-text-faint">
            {baselineHtml ? `${baselineHtml.length.toLocaleString()} chars in baseline` : "No baseline yet"}
          </p>
        </div>
        {baselineHtml ? (
          <div className="mt-4 max-h-48 overflow-auto rounded-sm border border-edge bg-void/60 p-3">
            <pre className="whitespace-pre-wrap break-all font-data text-[10px] leading-relaxed text-text-dim">
              {baselineHtml.slice(0, 2000)}
              {baselineHtml.length > 2000 ? "\n…" : ""}
            </pre>
          </div>
        ) : (
          <p className="mt-4 font-data text-[12px] text-text-faint">
            Establish a baseline scan to enable defacement detection on this asset.
          </p>
        )}
      </div>
    </section>
  );
}
