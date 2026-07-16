"use client";

import { cn } from "@/lib/format";

interface SegmentedControlProps<T extends string> {
  value: T;
  options: { value: T; label: string }[];
  onChange: (value: T) => void;
  ariaLabel: string;
}

export function SegmentedControl<T extends string>({
  value,
  options,
  onChange,
  ariaLabel,
}: SegmentedControlProps<T>) {
  return (
    <div
      role="tablist"
      aria-label={ariaLabel}
      className="inline-flex rounded-sm border border-edge bg-carbon p-0.5"
    >
      {options.map((opt) => {
        const active = opt.value === value;
        return (
          <button
            key={opt.value}
            role="tab"
            type="button"
            aria-selected={active}
            onClick={() => onChange(opt.value)}
            className={cn(
              "relative rounded-sm px-3 py-1.5 font-data text-[11px] uppercase tracking-[0.1em] transition-colors",
              active ? "bg-slate-hi text-text" : "text-text-faint hover:text-text-dim",
            )}
          >
            {opt.label}
            {active ? (
              <span className="absolute inset-x-2 bottom-0 h-px bg-live" aria-hidden />
            ) : null}
          </button>
        );
      })}
    </div>
  );
}
