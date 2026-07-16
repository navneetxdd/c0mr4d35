import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import type { Telemetry } from "@/lib/types";

interface MetricsStripProps {
  data: Telemetry;
}

export function MetricsStrip({ data }: MetricsStripProps) {
  const items = [
    { label: "MTTD", value: `${data.mttdSec}s` },
    { label: "SCANS / 24H", value: String(data.scans24h) },
    { label: "OPEN INCIDENTS", value: String(data.openIncidents).padStart(2, "0") },
  ];

  return (
    <section
      className="panel stagger-in grid grid-cols-3 divide-x divide-edge"
      style={{ animationDelay: "280ms" }}
    >
      {items.map((item) => (
        <div key={item.label} className="px-4 py-4">
          <MonoEyebrow>{item.label}</MonoEyebrow>
          <p className="mt-2 type-data-lg text-text">{item.value}</p>
        </div>
      ))}
    </section>
  );
}
