import { AssetDetailView } from "@/components/asset/AssetDetailView";

export const metadata = {
  title: "Asset",
};

export default async function AssetPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <AssetDetailView id={id} />;
}
