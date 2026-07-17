/**
 * Fan-out alert dispatcher. Tries every configured channel; scan persistence
 * must never depend on delivery success.
 */

import { dispatchDiscordAlert } from "./discord";
import { dispatchSlackAlert } from "./slack";

export type AlertSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface DispatchResult {
  delivered: boolean;
  /** Comma-joined channel ids that accepted the message, or "in-app". */
  channel: string;
}

export async function dispatchOutboundAlert(
  title: string,
  description: string,
  severity: AlertSeverity,
): Promise<DispatchResult> {
  const [discord, slack] = await Promise.all([
    dispatchDiscordAlert(title, description, severity),
    dispatchSlackAlert(title, description, severity),
  ]);

  const channels: string[] = [];
  if (discord) channels.push("discord");
  if (slack) channels.push("slack");

  return {
    delivered: channels.length > 0,
    channel: channels.length > 0 ? channels.join("+") : "in-app",
  };
}
