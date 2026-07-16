import type { Posture } from "@/lib/types";
import { cn, postureLabel } from "@/lib/format";

const colorMap: Record<Posture, string> = {
  secure: "bg-secure shadow-[0_0_8px_rgba(63,185,160,0.45)]",
  watch: "bg-watch shadow-[0_0_8px_rgba(233,180,76,0.4)]",
  critical: "bg-critical led-critical",
  scanning: "bg-live shadow-[0_0_8px_rgba(184,240,76,0.5)]",
  pending: "bg-text-faint shadow-[0_0_6px_rgba(148,163,184,0.35)]",
};

interface StatusLedProps {
  posture: Posture;
  label?: boolean;
  className?: string;
  size?: "sm" | "md";
}

export function StatusLed({ posture, label = false, className, size = "sm" }: StatusLedProps) {
  return (
    <span className={cn("inline-flex items-center gap-2", className)}>
      <span
        className={cn(
          "rounded-full shrink-0",
          size === "sm" ? "h-1.5 w-1.5" : "h-2 w-2",
          colorMap[posture],
        )}
        aria-hidden
      />
      {label ? (
        <span className="type-data-sm text-text-dim">{postureLabel(posture)}</span>
      ) : (
        <span className="sr-only">{postureLabel(posture)}</span>
      )}
    </span>
  );
}
