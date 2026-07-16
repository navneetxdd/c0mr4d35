import { AssetsClient } from "@/components/assets/AssetsClient";
import { fetchAssetsWithScans, fetchShellContext } from "@/lib/data/queries";

export default async function AssetsPage() {
  const [shell, assets] = await Promise.all([fetchShellContext(), fetchAssetsWithScans()]);
  return <AssetsClient shell={shell} assets={assets} />;
}
