import { IncidentsClient } from "@/components/incidents/IncidentsClient";
import { fetchIncidents, fetchShellContext } from "@/lib/data/queries";

export default async function IncidentsPage() {
  const [shell, incidents] = await Promise.all([fetchShellContext(), fetchIncidents()]);
  return <IncidentsClient shell={shell} incidents={incidents} />;
}
