import Link from "next/link";
import type { Asset } from "@/lib/types";
import { StatusLed } from "@/components/ui/StatusLed";
import { Sparkline } from "@/components/ui/Sparkline";
import { RelativeTime } from "@/components/ui/RelativeTime";
import { cn } from "@/lib/format";

interface AssetTileProps {
  asset: Asset;
  index: number;
  large?: boolean;
}

export function AssetTile({ asset, index, large }: AssetTileProps) {
  return (
    <Link
      href={`/assets/${asset.id}`}
      className={cn(
        "panel group stagger-in block overflow-hidden transition-colors hover:border-edge-hi",
        large ? "min-h-[260px] sm:col-span-2" : "min-h-[160px]",
        asset.posture === "critical" && "glow-critical",
      )}
      style={{ animationDelay: `${index * 40}ms` }}
    >
      <div className="relative flex h-full flex-col gap-3 p-4">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <p className="truncate text-[15px] font-medium tracking-tight text-text">
              {asset.name}
            </p>
            <p className="truncate font-data text-[12px] text-text-dim">{asset.host}</p>
          </div>
          <StatusLed posture={asset.posture} label />
        </div>

        <div className="flex items-end justify-between gap-3">
          <Sparkline
            values={asset.driftHistory}
            posture={asset.posture}
            className={large ? "h-10 w-[200px]" : undefined}
          />
          <div className="text-right">
            <p className="type-data-sm text-text-faint">DRIFT</p>
            <p className={cn("text-text", large ? "type-data-lg" : "type-data")}>
              {asset.driftScore.toFixed(1)}%
            </p>
          </div>
        </div>

        <div className="mt-auto flex items-end justify-between gap-3">
          <p className="type-data-sm text-text-faint">
            <RelativeTime iso={asset.lastCheckAt} prefix="LAST · " />
          </p>
          <div
            className={cn(
              "relative overflow-hidden rounded-sm border border-edge bg-void",
              large ? "h-16 w-28" : "h-10 w-16",
            )}
          >
            {asset.thumbnail ? (
              /* eslint-disable-next-line @next/next/no-img-element */
              <img
                src={asset.thumbnail}
                alt=""
                className="h-full w-full object-cover opacity-70 transition-opacity group-hover:opacity-95"
              />
            ) : (
              <div
                className={cn(
                  "flex h-full w-full items-center justify-center font-data text-[9px] uppercase tracking-wider",
                  asset.posture === "critical"
                    ? "text-critical/80"
                    : asset.posture === "watch"
                      ? "text-watch/80"
                      : "text-secure/60",
                )}
              >
                {asset.posture}
              </div>
            )}
            {asset.posture === "scanning" ? (
              <span
                className="radar-sweep pointer-events-none absolute inset-[-40%] rounded-full border border-live/30 border-t-live/80"
                aria-hidden
              />
            ) : null}
          </div>
        </div>
      </div>
    </Link>
  );
}
