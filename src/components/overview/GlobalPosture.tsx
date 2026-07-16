"use client";

import type { Asset } from "@/lib/types";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { PostureChip } from "@/components/ui/PostureChip";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";
import { StatusLed } from "@/components/ui/StatusLed";
import { cn } from "@/lib/format";

interface GlobalPostureProps {
  assets: Asset[];
  posture: "secure" | "watch" | "critical";
  watchCount: number;
}

export function GlobalPosture({ assets, posture, watchCount }: GlobalPostureProps) {
  const secure = assets.filter((a) => a.posture === "secure").length;

  return (
    <section
      className={cn(
        "panel stagger-in relative p-5",
        posture === "critical" && "glow-critical",
      )}
      style={{ animationDelay: "0ms" }}
    >
      <RegistrationMarks />
      <MonoEyebrow index="01">Global posture</MonoEyebrow>
      <div className="mt-4 flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="type-data-lg text-text">
            {String(secure).padStart(2, "0")}
            <span className="text-text-faint"> / {String(assets.length).padStart(2, "0")}</span>
          </p>
          <p className="mt-1 type-small text-text-dim">assets holding baseline</p>
        </div>
        <PostureChip posture={posture} watchCount={watchCount} size="lg" />
      </div>
      <div className="mt-6 flex flex-wrap gap-2">
        {assets.map((a) => (
          <span
            key={a.id}
            title={`${a.name} · ${a.posture}`}
            className="inline-flex items-center gap-1.5 rounded-sm border border-edge px-2 py-1 hover:border-edge-hi"
          >
            <StatusLed posture={a.posture} />
            <span className="font-data text-[10px] uppercase tracking-wider text-text-faint">
              {a.name.split("-")[0]}
            </span>
          </span>
        ))}
      </div>
    </section>
  );
}
