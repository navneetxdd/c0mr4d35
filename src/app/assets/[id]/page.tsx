import { AssetDetailClient, AssetNotFound } from "@/components/asset/AssetDetailClient";
import { fetchAssetDetail, fetchShellContext } from "@/lib/data/queries";

export const metadata = {
  title: "Asset",
};

export default async function AssetPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const [shell, detail] = await Promise.all([fetchShellContext(), fetchAssetDetail(id)]);

  if (!detail) {
    return <AssetNotFound shell={shell} />;
  }

  return (
    <AssetDetailClient
      shell={shell}
      assetView={detail.assetView}
      scans={detail.scans}
      findings={detail.findings}
      baselineHtml={detail.baselineHtml}
      aiVerdict={detail.aiVerdict}
      isAnalyst={shell.isAnalyst}
    />
  );
}
