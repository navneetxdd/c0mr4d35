"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  SquaresFour,
  Globe,
  Crosshair,
  Warning,
  Scroll,
  Users,
  GearSix,
} from "@phosphor-icons/react";
import { cn } from "@/lib/format";

const nav = [
  { href: "/", label: "Overview", icon: SquaresFour },
  { href: "/scan", label: "Live Scan", icon: Crosshair },
  { href: "/assets", label: "Assets", icon: Globe },
  { href: "/incidents", label: "Incidents", icon: Warning },
  { href: "/audit", label: "Audit", icon: Scroll },
  { href: "/members", label: "Members", icon: Users, admin: true },
  { href: "/settings", label: "Settings", icon: GearSix },
] as const;

interface RailProps {
  isAdmin?: boolean;
}

export function Rail({ isAdmin = true }: RailProps) {
  const pathname = usePathname();
  const items = nav.filter((n) => !("admin" in n && n.admin) || isAdmin);

  return (
    <>
      {/* Desktop rail */}
      <aside className="hidden md:flex w-16 shrink-0 flex-col items-center border-r border-edge bg-carbon py-3">
        <Link
          href="/"
          className="mb-6 flex h-9 w-9 items-center justify-center rounded-sm border border-edge text-live"
          aria-label="Datum home"
        >
          <CrosshairMark />
        </Link>
        <nav className="flex flex-1 flex-col gap-1" aria-label="Primary">
          {items.map(({ href, label, icon: Icon }) => {
            const active =
              href === "/"
                ? pathname === "/"
                : pathname === href || pathname.startsWith(`${href}/`);
            return (
              <Link
                key={href}
                href={href}
                title={label}
                aria-label={label}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "group relative flex h-11 w-11 items-center justify-center rounded-sm text-text-faint transition-colors",
                  "hover:bg-slate-hi hover:text-text",
                  active && "text-text",
                )}
              >
                {active ? (
                  <span className="absolute left-0 top-2 bottom-2 w-0.5 bg-live" aria-hidden />
                ) : null}
                <Icon size={20} weight={active ? "fill" : "regular"} />
                <span className="pointer-events-none absolute left-14 z-20 hidden whitespace-nowrap rounded-sm border border-edge bg-slate px-2 py-1 font-data text-[10px] uppercase tracking-wider text-text group-hover:block">
                  {label}
                </span>
              </Link>
            );
          })}
        </nav>
        <div className="mt-auto flex flex-col items-center gap-1 pb-1" title="Monitoring active">
          <span className="h-1.5 w-1.5 rounded-full bg-live shadow-[0_0_8px_rgba(184,240,76,0.6)]" />
          <span className="sr-only">Monitoring active</span>
        </div>
      </aside>

      {/* Mobile bottom tab bar */}
      <nav
        className="fixed inset-x-0 bottom-0 z-40 flex h-14 items-stretch border-t border-edge bg-carbon md:hidden"
        aria-label="Primary mobile"
      >
        {items.slice(0, 5).map(({ href, label, icon: Icon }) => {
          const active =
            href === "/"
              ? pathname === "/"
              : pathname === href || pathname.startsWith(`${href}/`);
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "relative flex flex-1 flex-col items-center justify-center gap-0.5 text-[9px] font-data uppercase tracking-wider",
                active ? "text-text" : "text-text-faint",
              )}
            >
              {active ? (
                <span className="absolute left-1/4 right-1/4 top-0 h-0.5 bg-live" aria-hidden />
              ) : null}
              <Icon size={18} weight={active ? "fill" : "regular"} />
              {label}
            </Link>
          );
        })}
      </nav>
    </>
  );
}

function CrosshairMark() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden>
      <circle cx="8" cy="8" r="5.5" stroke="currentColor" strokeWidth="1" />
      <path d="M8 1.5V4M8 12V14.5M1.5 8H4M12 8H14.5" stroke="currentColor" strokeWidth="1" />
      <circle cx="8" cy="8" r="1.2" fill="currentColor" />
    </svg>
  );
}
