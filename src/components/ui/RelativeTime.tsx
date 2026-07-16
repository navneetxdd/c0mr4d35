"use client";

import { useEffect, useState } from "react";
import { formatClock, relativeTime } from "@/lib/format";

interface RelativeTimeProps {
  iso: string;
  className?: string;
  prefix?: string;
}

export function RelativeTime({ iso, className, prefix = "" }: RelativeTimeProps) {
  const [label, setLabel] = useState(() => formatClock(iso));

  useEffect(() => {
    const tick = () => setLabel(relativeTime(iso));
    tick();
    const id = window.setInterval(tick, 15_000);
    return () => window.clearInterval(id);
  }, [iso]);

  return (
    <time dateTime={iso} className={className} suppressHydrationWarning>
      {prefix}
      {label}
    </time>
  );
}
