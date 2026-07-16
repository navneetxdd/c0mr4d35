import type { Posture, RiskLevel } from "./types";

export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

export function relativeTime(iso: string): string {
  const delta = Date.now() - new Date(iso).getTime();
  const sec = Math.max(0, Math.floor(delta / 1000));
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.floor(hr / 24)}d ago`;
}

export function formatClock(iso: string): string {
  try {
    return new Date(iso).toISOString().replace("T", " ").replace(/\.\d{3}Z$/, "Z");
  } catch {
    return iso;
  }
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

export function postureLabel(p: Posture): string {
  switch (p) {
    case "secure":
      return "SECURE";
    case "watch":
      return "WATCH";
    case "critical":
      return "CRITICAL";
    case "scanning":
      return "SCANNING";
    case "pending":
      return "PENDING";
    default:
      return "UNKNOWN";
  }
}

export function severityTone(s: RiskLevel): "critical" | "watch" | "scan" | "neutral" {
  if (s === "CRITICAL" || s === "HIGH") return "critical";
  if (s === "MEDIUM") return "watch";
  if (s === "LOW") return "scan";
  return "neutral";
}

export function globalPostureCopy(
  posture: "secure" | "watch" | "critical",
  watchCount: number,
): string {
  if (posture === "critical") return "INCIDENT";
  if (posture === "watch") return `${watchCount} ANOMAL${watchCount === 1 ? "Y" : "IES"}`;
  return "ALL SECURE";
}
