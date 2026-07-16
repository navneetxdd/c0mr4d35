/**
 * Discord webhook dispatch for critical/high findings. Server-side only.
 * Returns true when delivered; never throws — scan persistence must not depend on this.
 */

interface DiscordEmbed {
  title: string;
  description: string;
  color: number;
}

export async function dispatchDiscordAlert(
  title: string,
  description: string,
  severity: "critical" | "high" | "medium" | "low" | "info",
): Promise<boolean> {
  const url = process.env.DISCORD_WEBHOOK_URL;
  if (!url) return false;

  const color =
    severity === "critical" ? 0xf0563f : severity === "high" ? 0xf5a623 : 0x3d8bfd;

  const embed: DiscordEmbed = {
    title: title.slice(0, 256),
    description: description.slice(0, 4000),
    color,
  };

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        username: "Datum",
        embeds: [embed],
      }),
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) {
      // One retry on transient failure.
      const retry = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "Datum", embeds: [embed] }),
        signal: AbortSignal.timeout(8000),
      });
      return retry.ok;
    }
    return true;
  } catch {
    return false;
  }
}
