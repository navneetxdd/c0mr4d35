import { cn } from "@/lib/format";

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label: string;
  error?: string;
  hint?: string;
}

export function Input({ label, error, hint, id, className, ...rest }: InputProps) {
  const inputId = id ?? label.toLowerCase().replace(/\s+/g, "-");
  return (
    <label className="flex flex-col gap-1.5" htmlFor={inputId}>
      <span className="type-label">{label}</span>
      <input
        id={inputId}
        suppressHydrationWarning
        className={cn(
          "h-10 rounded-sm border bg-carbon px-3 text-[16px] text-text",
          "placeholder:text-text-faint",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-live",
          error ? "border-critical" : "border-edge",
          className,
        )}
        aria-invalid={Boolean(error)}
        aria-describedby={error ? `${inputId}-err` : hint ? `${inputId}-hint` : undefined}
        {...rest}
      />
      {error ? (
        <span id={`${inputId}-err`} className="type-data-sm text-critical border-b border-critical/50 pb-0.5">
          {error}
        </span>
      ) : hint ? (
        <span id={`${inputId}-hint`} className="type-data-sm text-text-faint">
          {hint}
        </span>
      ) : null}
    </label>
  );
}
