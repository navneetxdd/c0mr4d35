/**
 * Slack Incoming Webhook dispatch for defacement / high-severity alerts.
 * Server-side only. Returns true when delivered; never throws — scan
 * persistence must not depend on notification delivery.
 *
 * Phone push: install the Slack mobile app and enable notifications for the
 * channel that owns this webhook. This is NOT the Slack MCP (Cursor-only).
 */

interface SlackBlock {
  type: string;
  text?: { type: string; text: string; emoji?: boolean };
  elements?: Array<{ type: string; text: string }>;
}

export async function dispatchSlackAlert(
  title: string,
  description: string,
  severity: "critical" | "high" | "medium" | "low" | "info",
): Promise<boolean> {
  const url = process.env.SLACK_WEBHOOK_URL?.trim();
  if (!url) return false;

  const emoji =
    severity === "critical" ? ":rotating_light:" : severity === "high" ? ":warning:" : ":mag:";

  const payload = {
    text: `${emoji} ${title}: ${description}`.slice(0, 3000),
    blocks: [
      {
        type: "header",
        text: { type: "plain_text", text: `${title}`.slice(0, 150), emoji: true },
      },
      {
        type: "section",
        text: { type: "mrkdwn", text: description.slice(0, 2900) },
      },
      {
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: `*Severity:* ${severity.toUpperCase()} · Datum baseline integrity`,
          },
        ],
      },
    ] satisfies SlackBlock[],
  };

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) {
      const retry = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(8000),
      });
      return retry.ok;
    }
    return true;
  } catch {
    return false;
  }
}
