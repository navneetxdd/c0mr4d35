"use client";

import { useEffect, useState } from "react";
import type { FeedEvent } from "@/lib/types";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";
import { StatusLed } from "@/components/ui/StatusLed";
import { formatClock } from "@/lib/format";
import { createClient } from "@/lib/supabase/client";

interface EventFeedProps {
  initial: FeedEvent[];
}

function mapScanRow(row: {
  id: string;
  asset_id: string;
  posture: string | null;
  status: string;
  started_at: string;
  finished_at: string | null;
}): FeedEvent {
  const posture =
    row.status === "scanning" || row.status === "queued"
      ? "scanning"
      : row.posture === "critical"
        ? "critical"
        : row.posture === "watch"
          ? "watch"
          : "secure";
  return {
    id: `scan-${row.id}`,
    at: row.finished_at ?? row.started_at,
    posture,
    message: `SCAN ${row.status.toUpperCase()} · asset ${row.asset_id.slice(0, 8)}`,
  };
}

export function EventFeed({ initial }: EventFeedProps) {
  const [events, setEvents] = useState(initial);

  useEffect(() => {
    setEvents(initial);
  }, [initial]);

  useEffect(() => {
    const supabase = createClient();
    const channel = supabase
      .channel("datum-feed")
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "scans" },
        (payload) => {
          const row = payload.new as Parameters<typeof mapScanRow>[0];
          setEvents((prev) => [mapScanRow(row), ...prev.slice(0, 39)]);
        },
      )
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "alerts" },
        (payload) => {
          const row = payload.new as { id: string; severity: string; message: string; created_at: string };
          setEvents((prev) => [
            {
              id: `alert-${row.id}`,
              at: row.created_at,
              posture: row.severity === "critical" ? "critical" : "watch",
              message: `ALERT · ${row.message}`,
            },
            ...prev.slice(0, 39),
          ]);
        },
      )
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "findings" },
        (payload) => {
          const row = payload.new as {
            id: string;
            category: string;
            risk: string;
            title: string;
            created_at: string;
          };
          if (row.category !== "DEFACEMENT" && row.risk !== "critical" && row.risk !== "high") return;
          setEvents((prev) => [
            {
              id: `finding-${row.id}`,
              at: row.created_at,
              posture: row.risk === "critical" ? "critical" : "watch",
              message: `${row.category} · ${row.title}`,
            },
            ...prev.slice(0, 39),
          ]);
        },
      )
      .subscribe();

    return () => {
      void supabase.removeChannel(channel);
    };
  }, []);

  return (
    <section
      className="panel stagger-in relative flex h-[min(720px,calc(100dvh-8rem))] min-h-[420px] flex-col"
      style={{ animationDelay: "40ms" }}
    >
      <RegistrationMarks />
      <div className="border-b border-edge px-4 py-3">
        <MonoEyebrow index="02">Live event feed · {String(events.length).padStart(2, "0")}</MonoEyebrow>
      </div>
      <ul className="scroll-thin flex-1 space-y-0 overflow-y-auto p-2">
        {events.length === 0 ? (
          <li className="px-4 py-8 text-center font-data text-[12px] text-text-faint">
            No events yet — scans and alerts will appear here in real time.
          </li>
        ) : (
          events.map((e) => (
            <li
              key={e.id}
              className="slide-in flex gap-3 border-b border-edge/60 px-2 py-2.5 last:border-0"
            >
              <StatusLed posture={e.posture} />
              <div className="min-w-0 flex-1">
                <p className="font-data text-[10px] text-text-faint">{formatClock(e.at)}</p>
                <p className="mt-0.5 font-data text-[12px] leading-4 text-text-dim">{e.message}</p>
              </div>
            </li>
          ))
        )}
      </ul>
    </section>
  );
}
