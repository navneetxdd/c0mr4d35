import type { AiVerdict } from "@/lib/types";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";
import { StatusLed } from "@/components/ui/StatusLed";
import { StatusPill } from "@/components/ui/StatusPill";
import { cn } from "@/lib/format";

interface VerdictPanelProps {
  verdict: AiVerdict | null;
}

function toneFor(verdict: AiVerdict["verdict"]) {
  if (verdict === "DEFACEMENT") return "critical" as const;
  if (verdict === "DRIFT DETECTED") return "watch" as const;
  return "secure" as const;
}

export function VerdictPanel({ verdict }: VerdictPanelProps) {
  if (!verdict) {
    return (
      <section className="panel relative p-4">
        <RegistrationMarks />
        <MonoEyebrow index="05">AI verdict</MonoEyebrow>
        <p className="mt-4 font-data text-[12px] uppercase tracking-wider text-text-dim">
          AI ENRICHMENT UNAVAILABLE
        </p>
        <p className="mt-2 type-small text-text-dim">
          Findings below are authoritative. Gemini timed out or failed — detection still
          stands.
        </p>
      </section>
    );
  }

  const tone = toneFor(verdict.verdict);

  return (
    <section className="panel relative p-4">
      <RegistrationMarks />
      <MonoEyebrow index="05">AI verdict</MonoEyebrow>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <StatusPill tone={tone}>{verdict.verdict}</StatusPill>
        <span className="font-data text-[11px] text-text-faint">GEMINI 2.5 FLASH</span>
      </div>
      <div className="mt-4">
        <div className="flex items-center justify-between">
          <span className="type-label">Confidence</span>
          <span className="font-data text-[12px] text-text">
            {(verdict.confidence * 100).toFixed(0)}%
          </span>
        </div>
        <div className="mt-1.5 h-1.5 overflow-hidden rounded-sm bg-void">
          <div
            className={cn(
              "h-full rounded-sm",
              tone === "critical"
                ? "bg-critical"
                : tone === "watch"
                  ? "bg-watch"
                  : "bg-secure",
            )}
            style={{ width: `${verdict.confidence * 100}%` }}
          />
        </div>
      </div>
      <p className="mt-4 type-small text-text-dim">{verdict.summary}</p>
      <div className="mt-4 border-t border-edge pt-3">
        <p className="type-label mb-2">Indicators</p>
        <ul className="space-y-2">
          {verdict.indicators.map((ind) => (
            <li key={ind.label} className="flex items-start gap-2">
              <StatusLed posture={ind.posture} />
              <span className="font-data text-[12px] text-text-dim">{ind.label}</span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
