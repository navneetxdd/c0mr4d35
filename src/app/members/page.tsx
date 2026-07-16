import { MembersClient } from "@/components/members/MembersClient";
import { fetchMembers, fetchShellContext } from "@/lib/data/queries";

export default async function MembersPage() {
  const [shell, members] = await Promise.all([fetchShellContext(), fetchMembers()]);
  return <MembersClient shell={shell} members={members} />;
}
