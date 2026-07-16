import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";
import type { DefacementScore } from "@/lib/scan/defacement-score";
import { cn } from "@/lib/format";

interface DefacementConfidencePanelProps {
  score: DefacementScore;
  eyebrowIndex?: string;
}

export function DefacementConfidencePanel({
  score,
  eyebrowIndex = "02b",
}: DefacementConfidencePanelProps) {
  const tone =
    score.classification === "DEFACEMENT"
      ? "critical"
      : score.classification === "SUSPECT" || score.classification === "WATCH"
        ? "watch"
        : "secure";

  return (
    <section className="panel relative p-4">
      <RegistrationMarks />
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <MonoEyebrow index={eyebrowIndex}>Defacement confidence</MonoEyebrow>
          <p
            className={cn(
              "mt-2 type-h2",
              tone === "critical" ? "text-critical" : tone === "watch" ? "text-watch" : "text-secure",
            )}
          >
            {score.score}
            <span className="ml-2 font-data text-[12px] text-text-faint">/ 100</span>
          </p>
          <p className="mt-1 font-data text-[11px] uppercase tracking-wider text-text-dim">
            {score.classification} · {score.layersFired} layer{score.layersFired === 1 ? "" : "s"} fired
            {score.shouldIncident ? " · INCIDENT THRESHOLD" : ""}
          </p>
        </div>
      </div>
      <ul className="mt-4 space-y-2">
        {score.layers.map((layer) => (
          <li key={layer.id} className="flex items-start justify-between gap-3 border-t border-edge/60 pt-2">
            <div className="min-w-0">
              <p className="font-data text-[12px] text-text">
                {layer.fired ? "●" : "○"} {layer.label}
              </p>
              <p className="type-data-sm text-text-faint">{layer.detail}</p>
            </div>
            <span className="shrink-0 font-data text-[12px] text-text-dim">{layer.score}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
