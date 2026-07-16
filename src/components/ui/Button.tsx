import { cn } from "@/lib/format";

type Variant = "primary" | "secondary" | "danger" | "ghost";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
}

const styles: Record<Variant, string> = {
  primary:
    "bg-text text-void hover:bg-white active:scale-[0.98] border border-transparent",
  secondary:
    "bg-transparent text-text border border-edge-hi hover:border-text-dim hover:bg-slate-hi",
  danger:
    "bg-transparent text-critical border border-critical/50 hover:bg-critical/10",
  ghost: "bg-transparent text-text-dim border border-transparent hover:text-text hover:bg-slate-hi",
};

export function Button({
  variant = "primary",
  className,
  type = "button",
  disabled,
  children,
  ...rest
}: ButtonProps) {
  return (
    <button
      type={type}
      disabled={disabled}
      className={cn(
        "inline-flex h-9 items-center justify-center gap-2 rounded-sm px-4",
        "font-medium tracking-tight text-[13px] transition-colors",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-live focus-visible:ring-offset-2 focus-visible:ring-offset-void",
        "disabled:cursor-not-allowed disabled:opacity-40",
        styles[variant],
        className,
      )}
      {...rest}
    >
      {children}
    </button>
  );
}
