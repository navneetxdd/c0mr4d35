"use client";

import { useEffect, useState } from "react";
import type { FeedEvent } from "@/lib/types";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";
import { StatusLed } from "@/components/ui/StatusLed";
import { formatClock } from "@/lib/format";

interface EventFeedProps {
  initial: FeedEvent[];
}

export function EventFeed({ initial }: EventFeedProps) {
  const [events, setEvents] = useState(initial);

  useEffect(() => {
    const templates: Omit<FeedEvent, "id" | "at">[] = [
      {
        posture: "secure",
        message: "BASELINE HELD · help-center · drift 0.8% · 1.4s",
      },
      {
        posture: "scanning",
        message: "SCAN QUEUED · billing-console · trigger CRON · job j_a81e",
      },
      {
        posture: "watch",
        message: "TLS WATCH · billing-console · expires 12d · MEDIUM",
      },
    ];
    let i = 0;
    const id = window.setInterval(() => {
      const t = templates[i % templates.length];
      if (!t) return;
      i += 1;
      setEvents((prev) => [
        {
          id: `live-${Date.now()}`,
          at: new Date().toISOString(),
          posture: t.posture,
          message: t.message,
        },
        ...prev.slice(0, 40),
      ]);
    }, 7000);
    return () => window.clearInterval(id);
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
        {events.map((e) => (
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
        ))}
      </ul>
    </section>
  );
}
