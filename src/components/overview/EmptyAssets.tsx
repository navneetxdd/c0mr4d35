import { Button } from "@/components/ui/Button";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";

interface EmptyAssetsProps {
  onEstablish?: () => void;
}

export function EmptyAssets({ onEstablish }: EmptyAssetsProps) {
  return (
    <section className="panel relative mx-auto max-w-lg px-8 py-16 text-center">
      <RegistrationMarks />
      <MonoEyebrow index="00">Watch list</MonoEyebrow>
      <h2 className="mt-4 type-h2 text-text">NO ASSETS UNDER WATCH</h2>
      <p className="mx-auto mt-3 max-w-sm type-small text-text-dim">
        Establish a datum — capture the known-good baseline — then Datum measures every
        drift from that reference.
      </p>
      <div className="mt-8 flex justify-center">
        <Button onClick={onEstablish}>+ Establish baseline</Button>
      </div>
    </section>
  );
}
