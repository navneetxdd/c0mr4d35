import { runScan } from "../src/lib/scan/index.ts";

async function summarize(target: string) {
  const s = await runScan({ target, singlePage: true });
  return {
    ok: s.ok,
    host: s.finalHost,
    status: s.httpStatus,
    fingerprint: s.fingerprint,
    score: s.postureScore,
    posture: s.posture,
    openPorts: (s.ports ?? []).filter((p) => p.state === "open").map((p) => p.port),
    subCount: (s.subdomains ?? []).length,
    findingIds: s.findings.map((f) => f.id).sort(),
    titles: s.findings.slice(0, 8).map((f) => `[${f.category}] ${f.title}`),
    notes: (s.evidenceNotes ?? []).slice(0, 5),
    error: s.error ?? null,
  };
}

async function main() {
  const a = await summarize("https://example.com");
  const b = await summarize("https://www.wikipedia.org");
  console.log(
    JSON.stringify(
      {
        a,
        b,
        shared: a.findingIds.filter((id) => b.findingIds.includes(id)),
        onlyA: a.findingIds.filter((id) => !b.findingIds.includes(id)),
        onlyB: b.findingIds.filter((id) => !a.findingIds.includes(id)),
      },
      null,
      2,
    ),
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
