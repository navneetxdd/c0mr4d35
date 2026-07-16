"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { PostureChip } from "@/components/ui/PostureChip";
import { useToast } from "@/components/ui/Toast";
import { signOutAction } from "@/app/actions/datum";
import type { AppRole } from "@/lib/supabase/types";
import { cn } from "@/lib/format";

interface TopbarProps {
  crumbs: { label: string; href?: string }[];
  posture: "secure" | "watch" | "critical" | "scanning";
  watchCount: number;
  profile: { email: string; role: AppRole } | null;
  isAnalyst: boolean;
  onScanAll?: () => void | Promise<void>;
  className?: string;
}

export function Topbar({
  crumbs,
  posture,
  watchCount,
  profile,
  isAnalyst,
  onScanAll,
  className,
}: TopbarProps) {
  const { push } = useToast();
  const router = useRouter();

  async function handleSignOut() {
    await signOutAction();
    router.push("/login");
    router.refresh();
  }

  return (
    <header
      className={cn(
        "flex h-14 shrink-0 items-center gap-3 border-b border-edge bg-carbon/80 px-4 backdrop-blur-sm",
        className,
      )}
    >
      <nav aria-label="Breadcrumb" className="min-w-0 flex-1 overflow-hidden">
        <ol className="flex items-center gap-2 font-data text-[12px] text-text-faint">
          {crumbs.map((c, i) => (
            <li key={`${c.label}-${i}`} className="flex items-center gap-2 truncate">
              {i > 0 ? <span aria-hidden>/</span> : null}
              {c.href ? (
                <Link href={c.href} className="truncate hover:text-text-dim">
                  {c.label}
                </Link>
              ) : (
                <span className="truncate text-text-dim">{c.label}</span>
              )}
            </li>
          ))}
        </ol>
      </nav>

      <PostureChip posture={posture === "scanning" ? "watch" : posture} watchCount={watchCount} />

      {isAnalyst ? (
        <Button
          variant="primary"
          onClick={async () => {
            if (onScanAll) {
              await onScanAll();
            }
            push("SCAN ALL · jobs enqueued");
          }}
        >
          Scan all
        </Button>
      ) : null}

      <div className="hidden sm:flex items-center gap-2 border-l border-edge pl-3">
        <span className="font-data text-[11px] text-text-dim">{profile?.email ?? "—"}</span>
        <span className="rounded-sm border border-edge px-1.5 py-0.5 font-data text-[10px] uppercase tracking-wider text-text-faint">
          {profile?.role ?? "—"}
        </span>
        <button
          type="button"
          onClick={handleSignOut}
          className="font-data text-[10px] uppercase tracking-wider text-text-faint hover:text-text-dim"
        >
          Sign out
        </button>
      </div>
    </header>
  );
}
