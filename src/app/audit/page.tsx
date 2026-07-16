import { AuditClient, mapAuditRow } from "@/components/audit/AuditClient";
import { fetchAuditLog, fetchShellContext } from "@/lib/data/queries";

export default async function AuditPage() {
  const [shell, rows] = await Promise.all([fetchShellContext(), fetchAuditLog()]);
  const entries = rows.map(mapAuditRow);
  return <AuditClient shell={shell} entries={entries} />;
}
