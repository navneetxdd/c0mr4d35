import type { Posture } from "@/lib/types";
import { cn } from "@/lib/format";

const stroke: Record<Posture, string> = {
  secure: "var(--secure)",
  watch: "var(--watch)",
  critical: "var(--critical)",
  scanning: "var(--live)",
  pending: "var(--text-faint)",
};

interface SparklineProps {
  values: number[];
  posture: Posture;
  className?: string;
  baseline?: number;
}

export function Sparkline({ values, posture, className, baseline = 2 }: SparklineProps) {
  if (!values.length) return null;
  const w = 120;
  const h = 28;
  const max = Math.max(...values, baseline, 1);
  const min = 0;
  const range = max - min || 1;
  const pts = values
    .map((v, i) => {
      const x = (i / Math.max(values.length - 1, 1)) * w;
      const y = h - ((v - min) / range) * (h - 4) - 2;
      return `${x},${y}`;
    })
    .join(" ");
  const last = values[values.length - 1] ?? 0;
  const lastX = w;
  const lastY = h - ((last - min) / range) * (h - 4) - 2;
  const baseY = h - ((baseline - min) / range) * (h - 4) - 2;

  return (
    <svg
      viewBox={`0 0 ${w} ${h}`}
      className={cn("h-7 w-[120px]", className)}
      aria-hidden
    >
      <line
        x1={0}
        y1={baseY}
        x2={w}
        y2={baseY}
        stroke="var(--text-faint)"
        strokeWidth={1}
        strokeDasharray="2 3"
        opacity={0.7}
      />
      <polyline
        fill="none"
        stroke={stroke[posture]}
        strokeWidth={1.5}
        strokeLinejoin="round"
        strokeLinecap="round"
        points={pts}
      />
      <circle cx={lastX} cy={lastY} r={2} fill={stroke[posture]} />
    </svg>
  );
}
