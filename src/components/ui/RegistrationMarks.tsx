import { cn } from "@/lib/format";

interface RegistrationMarksProps {
  className?: string;
}

export function RegistrationMarks({ className }: RegistrationMarksProps) {
  const tick = "pointer-events-none absolute h-2.5 w-2.5 border-text-faint";
  return (
    <div aria-hidden className={cn("pointer-events-none absolute inset-0", className)}>
      <span className={cn(tick, "left-2 top-2 border-l border-t")} />
      <span className={cn(tick, "right-2 top-2 border-r border-t")} />
      <span className={cn(tick, "bottom-2 left-2 border-b border-l")} />
      <span className={cn(tick, "bottom-2 right-2 border-b border-r")} />
    </div>
  );
}
