"use client";

import { useCallback, useRef, useState } from "react";
import { motion, useMotionValue, useTransform } from "framer-motion";
import type { ChangeRegion, DiffMode } from "@/lib/types";
import { SegmentedControl } from "@/components/ui/SegmentedControl";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";

interface DiffViewerProps {
  baselineSrc: string;
  currentSrc: string;
  driftPct: number;
  regions: ChangeRegion[];
}

export function DiffViewer({
  baselineSrc,
  currentSrc,
  driftPct,
  regions,
}: DiffViewerProps) {
  const [mode, setMode] = useState<DiffMode>("reveal");
  const containerRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(640);
  const x = useMotionValue(0.42);
  const clip = useTransform(x, (v) => `inset(0 ${(1 - v) * 100}% 0 0)`);
  const handleLeft = useTransform(x, (v) => `${v * 100}%`);

  const onDrag = useCallback(
    (clientX: number) => {
      const el = containerRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      if (rect.width <= 0) return;
      const next = Math.min(0.95, Math.max(0.05, (clientX - rect.left) / rect.width));
      x.set(next);
      setWidth(rect.width);
    },
    [x],
  );

  return (
    <section className="panel relative overflow-hidden">
      <RegistrationMarks />
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-edge px-4 py-3">
        <MonoEyebrow index="03">Baseline · drift viewer</MonoEyebrow>
        <SegmentedControl
          ariaLabel="Diff view mode"
          value={mode}
          onChange={setMode}
          options={[
            { value: "side-by-side", label: "Side-by-side" },
            { value: "reveal", label: "Reveal" },
            { value: "heatmap", label: "Heatmap" },
          ]}
        />
      </div>

      <div className="p-4">
        {mode === "reveal" ? (
          <div
            ref={containerRef}
            className="relative aspect-[16/10] w-full overflow-hidden rounded-sm border border-edge bg-void select-none"
            onPointerDown={(e) => {
              (e.target as HTMLElement).setPointerCapture?.(e.pointerId);
              onDrag(e.clientX);
            }}
            onPointerMove={(e) => {
              if (e.buttons !== 1) return;
              onDrag(e.clientX);
            }}
          >
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={currentSrc}
              alt="Current capture"
              className="absolute inset-0 h-full w-full object-cover"
              draggable={false}
            />
            <motion.div className="absolute inset-0" style={{ clipPath: clip }}>
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={baselineSrc}
                alt="Baseline capture"
                className="h-full w-full object-cover"
                draggable={false}
              />
            </motion.div>

            {/* baseline plumb line */}
            <div
              className="pointer-events-none absolute inset-x-0 top-1/2 h-px bg-text-faint/40"
              aria-hidden
            />

            <motion.div
              className="absolute top-0 bottom-0 z-10 w-px bg-live"
              style={{ left: handleLeft }}
            >
              <motion.div
                drag="x"
                dragConstraints={containerRef}
                dragElastic={0.08}
                dragMomentum={false}
                onDrag={(_, info) => {
                  const el = containerRef.current;
                  if (!el) return;
                  const rect = el.getBoundingClientRect();
                  const next = Math.min(
                    0.95,
                    Math.max(0.05, (info.point.x - rect.left) / rect.width),
                  );
                  x.set(next);
                }}
                className="absolute left-1/2 top-1/2 flex h-10 w-10 -translate-x-1/2 -translate-y-1/2 cursor-ew-resize items-center justify-center rounded-sm border border-live bg-carbon glow-live"
                aria-label="Reveal handle"
                role="slider"
                aria-valuemin={5}
                aria-valuemax={95}
                aria-valuenow={Math.round(x.get() * 100)}
              >
                <span className="font-data text-[10px] text-live">⇄</span>
              </motion.div>
              <span className="absolute left-1/2 top-3 -translate-x-1/2 rounded-sm border border-edge bg-carbon px-1.5 py-0.5 font-data text-[10px] text-text">
                {driftPct.toFixed(1)}%
              </span>
            </motion.div>

            <div className="pointer-events-none absolute bottom-2 left-2 flex gap-2">
              <span className="rounded-sm border border-edge bg-carbon/90 px-1.5 py-0.5 font-data text-[10px] text-text-dim">
                BASELINE
              </span>
              <span className="rounded-sm border border-edge bg-carbon/90 px-1.5 py-0.5 font-data text-[10px] text-text-dim">
                CURRENT · {Math.round(width)}px
              </span>
            </div>
          </div>
        ) : null}

        {mode === "side-by-side" ? (
          <div className="grid gap-3 md:grid-cols-2">
            <CaptureFrame label="BASELINE" src={baselineSrc} />
            <CaptureFrame label="CURRENT" src={currentSrc} />
          </div>
        ) : null}

        {mode === "heatmap" ? (
          <div className="relative aspect-[16/10] w-full overflow-hidden rounded-sm border border-edge bg-void">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={currentSrc}
              alt="Current capture with heatmap"
              className="h-full w-full object-cover opacity-80"
            />
            <div
              className="pointer-events-none absolute inset-0 mix-blend-screen opacity-50"
              style={{
                background:
                  "radial-gradient(ellipse at 50% 28%, rgba(240,86,63,0.55), transparent 45%), radial-gradient(ellipse at 26% 50%, rgba(240,86,63,0.4), transparent 30%), radial-gradient(ellipse at 78% 78%, rgba(240,86,63,0.5), transparent 35%)",
              }}
              aria-hidden
            />
            {regions.map((r) => (
              <div
                key={r.id}
                className="absolute border border-critical"
                style={{
                  left: `${r.x}%`,
                  top: `${r.y}%`,
                  width: `${r.w}%`,
                  height: `${r.h}%`,
                }}
              >
                <span className="absolute -top-5 left-0 rounded-sm border border-critical/50 bg-carbon px-1 font-data text-[10px] text-critical">
                  {r.id} · {r.label}
                </span>
              </div>
            ))}
          </div>
        ) : null}
      </div>
    </section>
  );
}

function CaptureFrame({ label, src }: { label: string; src: string }) {
  return (
    <div className="overflow-hidden rounded-sm border border-edge bg-void">
      <div className="border-b border-edge px-2 py-1 font-data text-[10px] text-text-faint">
        {label}
      </div>
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src={src} alt={label} className="aspect-[16/10] w-full object-cover" />
    </div>
  );
}
