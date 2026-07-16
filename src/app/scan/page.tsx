import { ScanConsole } from "@/components/scan/ScanConsole";
import { fetchShellContext } from "@/lib/data/queries";

export const metadata = {
  title: "Live Scan",
};

export default async function ScanPage() {
  const shell = await fetchShellContext();
  return <ScanConsole shell={shell} />;
}
