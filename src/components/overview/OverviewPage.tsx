import { OverviewClient } from "@/components/overview/OverviewClient";
import {
  fetchAssetsWithScans,
  fetchFeedEvents,
  fetchShellContext,
  fetchTelemetry,
} from "@/lib/data/queries";

export async function OverviewPage() {
  const [shell, assets, telemetry, feed] = await Promise.all([
    fetchShellContext(),
    fetchAssetsWithScans(),
    fetchTelemetry(),
    fetchFeedEvents(),
  ]);

  return <OverviewClient shell={shell} assets={assets} telemetry={telemetry} feed={feed} />;
}
