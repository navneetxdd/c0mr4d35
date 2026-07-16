import { cn, globalPostureCopy } from "@/lib/format";

interface PostureChipProps {
  posture: "secure" | "watch" | "critical";
  watchCount?: number;
  size?: "sm" | "lg";
  className?: string;
}

export function PostureChip({
  posture,
  watchCount = 0,
  size = "sm",
  className,
}: PostureChipProps) {
  const label = globalPostureCopy(posture, watchCount);
  const tone =
    posture === "critical"
      ? "text-critical border-critical/50 bg-critical/10"
      : posture === "watch"
        ? "text-watch border-watch/50 bg-watch/10"
        : "text-secure border-secure/50 bg-secure/10";

  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 rounded-sm border font-data uppercase tracking-[0.1em]",
        size === "lg" ? "px-3 py-2 text-[13px]" : "px-2 py-1 text-[11px]",
        tone,
        className,
      )}
    >
      <span
        className={cn(
          "h-1.5 w-1.5 rounded-full",
          posture === "critical"
            ? "bg-critical led-critical"
            : posture === "watch"
              ? "bg-watch"
              : "bg-secure",
        )}
        aria-hidden
      />
      {label}
    </span>
  );
}
