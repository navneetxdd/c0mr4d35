import { cn } from "@/lib/format";

interface MonoEyebrowProps {
  index?: string;
  children: React.ReactNode;
  className?: string;
}

export function MonoEyebrow({ index, children, className }: MonoEyebrowProps) {
  return (
    <div className={cn("type-label", className)}>
      {index ? (
        <>
          <span>{index}</span>
          <span className="mx-1.5 text-text-faint">·</span>
        </>
      ) : null}
      {children}
    </div>
  );
}
