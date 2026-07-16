import { RegistrationMarks } from "@/components/ui/RegistrationMarks";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { cn } from "@/lib/format";
import type { VisualEvidence } from "@/lib/types";

interface DomDriftPanelProps {
  evidence: VisualEvidence;
}

export function DomDriftPanel({ evidence }: DomDriftPanelProps) {
  const driftPct = evidence.domDriftPct;
  const tone =
    driftPct >= 25 ? "critical" : driftPct >= 8 ? "watch" : "secure";

  return (
    <section className="panel relative overflow-hidden">
      <RegistrationMarks />
      <div className="border-b border-edge px-4 py-3">
        <MonoEyebrow index="03">Baseline · DOM drift</MonoEyebrow>
      </div>
      <div className="p-4">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p
              className={cn(
                "type-h1",
                tone === "critical" ? "text-critical" : tone === "watch" ? "text-watch" : "text-secure",
              )}
            >
              {driftPct.toFixed(1)}%
            </p>
            <p className="mt-1 type-small text-text-dim">
              DOM drift vs stored baseline, with visual evidence when available.
            </p>
          </div>
          <div className="text-right">
            <p className="font-data text-[11px] text-text-faint">
              BASELINE · {evidence.baselineState.toUpperCase()}
            </p>
            <p className="font-data text-[11px] text-text-faint">
              VISUAL · {evidence.visualDriftPct != null ? `${evidence.visualDriftPct.toFixed(1)}%` : "N/A"}
            </p>
          </div>
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-3">
          <CaptureCard label="BASELINE" src={evidence.baselineCapture} />
          <CaptureCard label="CURRENT" src={evidence.currentCapture} />
          <CaptureCard label="DIFF" src={evidence.diffCapture} />
        </div>
        <div className="mt-4 grid gap-2 sm:grid-cols-2">
          <Metric label="Favicon fingerprint" value={evidence.faviconHash ?? "Unavailable"} />
          <Metric
            label="Favicon change"
            value={evidence.faviconChanged ? "Changed from baseline" : "No change detected"}
          />
        </div>
        {evidence.ports?.length ? (
          <div className="mt-4 overflow-auto rounded-sm border border-edge">
            <p className="border-b border-edge px-3 py-2 type-label">TCP port probe proof</p>
            <table className="w-full text-left font-data text-[11px]">
              <thead className="text-text-faint">
                <tr>
                  <th className="px-3 py-1">PORT</th>
                  <th className="px-3 py-1">STATE</th>
                  <th className="px-3 py-1">RTT</th>
                </tr>
              </thead>
              <tbody>
                {evidence.ports
                  .filter((p) => p.state === "open")
                  .map((p) => (
                    <tr key={p.port} className="border-t border-edge text-text">
                      <td className="px-3 py-1">{p.port}</td>
                      <td className="px-3 py-1 text-watch">{p.state}</td>
                      <td className="px-3 py-1">{p.rttMs}ms</td>
                    </tr>
                  ))}
              </tbody>
            </table>
            {!evidence.ports.some((p) => p.state === "open") ? (
              <p className="px-3 py-2 text-text-faint">No open ports in probed set.</p>
            ) : null}
          </div>
        ) : null}
        {evidence.subdomains?.length ? (
          <div className="mt-4 overflow-auto rounded-sm border border-edge">
            <p className="border-b border-edge px-3 py-2 type-label">Subdomain discovery proof</p>
            <table className="w-full text-left font-data text-[11px]">
              <thead className="text-text-faint">
                <tr>
                  <th className="px-3 py-1">NAME</th>
                  <th className="px-3 py-1">SOURCE</th>
                  <th className="px-3 py-1">IPS</th>
                </tr>
              </thead>
              <tbody>
                {evidence.subdomains.slice(0, 40).map((s) => (
                  <tr key={s.subdomain} className="border-t border-edge text-text">
                    <td className="px-3 py-1">{s.subdomain}</td>
                    <td className="px-3 py-1">{s.source}</td>
                    <td className="px-3 py-1">{s.ips.join(", ") || "unresolved"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
        {evidence.notes.length ? (
          <div className="mt-4 rounded-sm border border-edge bg-void/60 p-3">
            <p className="type-label mb-2">Evidence notes</p>
            <ul className="space-y-1">
              {evidence.notes.map((note) => (
                <li key={note} className="font-data text-[11px] text-text-faint">
                  {note}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {evidence.baselineHtml ? (
          <details className="mt-4 rounded-sm border border-edge bg-void/60 p-3">
            <summary className="cursor-pointer font-data text-[11px] text-text-faint">
              BASELINE HTML SNAPSHOT · {evidence.baselineHtml.length.toLocaleString()} chars
            </summary>
            <pre className="mt-3 max-h-48 overflow-auto whitespace-pre-wrap break-all font-data text-[10px] leading-relaxed text-text-dim">
              {evidence.baselineHtml.slice(0, 2000)}
              {evidence.baselineHtml.length > 2000 ? "\n…" : ""}
            </pre>
          </details>
        ) : null}
        {!evidence.baselineHtml && !evidence.baselineCapture ? (
          <p className="mt-4 font-data text-[12px] text-text-faint">
            Establish a baseline scan to enable DOM and visual defacement detection.
          </p>
        ) : null}
      </div>
    </section>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-sm border border-edge bg-void/40 px-3 py-2">
      <p className="type-data-sm text-text-faint">{label}</p>
      <p className="mt-0.5 font-data text-[12px] text-text">{value}</p>
    </div>
  );
}

function CaptureCard({ label, src }: { label: string; src: string | null }) {
  return (
    <div className="overflow-hidden rounded-sm border border-edge bg-void">
      <div className="border-b border-edge px-2 py-1 font-data text-[10px] text-text-faint">
        {label}
      </div>
      {src ? (
        // eslint-disable-next-line @next/next/no-img-element
        <img src={src} alt={label} className="aspect-16/10 w-full object-cover" />
      ) : (
        <div className="flex aspect-16/10 items-center justify-center font-data text-[10px] text-text-faint">
          No image
        </div>
      )}
    </div>
  );
}
