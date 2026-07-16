import { cn } from "@/lib/format";

type Tone = "secure" | "watch" | "critical" | "scan" | "neutral";

const toneMap: Record<Tone, string> = {
  secure: "text-secure border-secure/40 bg-secure/10",
  watch: "text-watch border-watch/40 bg-watch/10",
  critical: "text-critical border-critical/40 bg-critical/10",
  scan: "text-scan border-scan/40 bg-scan/10",
  neutral: "text-text-dim border-edge-hi bg-slate-hi",
};

interface StatusPillProps {
  tone: Tone;
  children: React.ReactNode;
  className?: string;
}

export function StatusPill({ tone, children, className }: StatusPillProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-sm border px-1.5 py-0.5",
        "font-data text-[11px] uppercase tracking-[0.08em]",
        toneMap[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}
