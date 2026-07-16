import { AuditClient } from "@/components/audit/AuditClient";
import { fetchAuditLog, fetchShellContext } from "@/lib/data/queries";

export default async function AuditPage() {
  const [shell, entries] = await Promise.all([fetchShellContext(), fetchAuditLog()]);
  return <AuditClient shell={shell} entries={entries} />;
}
