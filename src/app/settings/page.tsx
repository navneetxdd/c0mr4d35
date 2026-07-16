import { AppShell } from "@/components/shell/AppShell";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { BUILD_HASH } from "@/lib/build";
import { fetchShellContext } from "@/lib/data/queries";

export default async function SettingsPage() {
  const shell = await fetchShellContext();
  const supabaseRef = process.env.NEXT_PUBLIC_SUPABASE_URL?.match(/https:\/\/([^.]+)/)?.[1] ?? "not set";
  const gemini = Boolean(process.env.GEMINI_API_KEY);
  const discord = Boolean(process.env.DISCORD_WEBHOOK_URL);
  const cron = Boolean(process.env.CRON_SECRET);

  return (
    <AppShell crumbs={[{ label: "SETTINGS" }]} shell={shell}>
      <MonoEyebrow index="16">Workspace</MonoEyebrow>
      <h1 className="mt-2 type-h1 text-text">Settings</h1>
      <div className="panel mt-6 divide-y divide-edge">
        <Row label="Supabase project" value={supabaseRef} />
        <Row label="Default scan interval" value="15 min (per asset)" />
        <Row label="Gemini BYOK" value={gemini ? "configured" : "not configured"} />
        <Row label="Discord alerts" value={discord ? "configured" : "not configured"} />
        <Row label="Cron scheduler" value={cron ? "configured" : "not configured"} />
        <Row label="Build" value={BUILD_HASH} />
        <Row label="Theme" value="DARK · NOC (locked)" />
      </div>
    </AppShell>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 px-4 py-3">
      <span className="type-label">{label}</span>
      <span className="font-data text-[13px] text-text-dim">{value}</span>
    </div>
  );
}
