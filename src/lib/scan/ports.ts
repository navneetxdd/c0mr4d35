import { Socket } from "node:net";
import type { ScanFinding } from "./risk";

/** Curated nmap-style top ports suitable for a bounded serverless budget. */
export const TOP_PORTS = [
  21, 22, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379,
  8080, 8443, 27017,
] as const;

export type PortState = "open" | "closed" | "timeout";

export interface PortProbeResult {
  port: number;
  state: PortState;
  rttMs: number;
  probedAt: string;
}

const RISKY_OPEN = new Set([22, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017]);

function probeOne(host: string, port: number, timeoutMs: number): Promise<PortProbeResult> {
  const probedAt = new Date().toISOString();
  const started = Date.now();

  return new Promise((resolve) => {
    let settled = false;
    const socket = new Socket();

    const finish = (state: PortState) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardTimer);
      try {
        socket.removeAllListeners();
        socket.destroy();
      } catch {
        /* ignore */
      }
      resolve({ port, state, rttMs: Date.now() - started, probedAt });
    };

    const hardTimer = setTimeout(() => finish("timeout"), timeoutMs);

    try {
      socket.setTimeout(timeoutMs);
      socket.once("connect", () => finish("open"));
      socket.once("timeout", () => finish("timeout"));
      socket.once("error", () => finish("closed"));
      socket.connect(port, host);
    } catch {
      finish("closed");
    }
  });
}

async function mapPool<T, R>(items: T[], concurrency: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  async function worker() {
    while (i < items.length) {
      const idx = i++;
      const item = items[idx];
      if (item === undefined) return;
      out[idx] = await fn(item);
    }
  }
  const n = Math.min(concurrency, Math.max(items.length, 1));
  await Promise.all(Array.from({ length: n }, () => worker()));
  return out;
}

export async function probePorts(
  host: string,
  opts?: { timeoutMs?: number; concurrency?: number; ports?: readonly number[] },
): Promise<{ results: PortProbeResult[]; findings: ScanFinding[]; notes: string[] }> {
  const timeoutMs = opts?.timeoutMs ?? 700;
  const concurrency = opts?.concurrency ?? 8;
  const ports = opts?.ports ?? TOP_PORTS;
  const notes: string[] = [];

  let results: PortProbeResult[];
  try {
    results = await mapPool([...ports], concurrency, (port) => probeOne(host, port, timeoutMs));
  } catch (error) {
    notes.push(`Port probe failed: ${error instanceof Error ? error.message : "unknown error"}`);
    return { results: [], findings: [], notes };
  }

  const open = results.filter((r) => r.state === "open");
  const findings: ScanFinding[] = [];

  for (const r of open) {
    if (!RISKY_OPEN.has(r.port)) continue;
    findings.push({
      id: `port-open-${r.port}`,
      category: "PORTS",
      risk: r.port === 3389 || r.port === 445 ? "high" : "medium",
      title: `Unexpected open port ${r.port}`,
      detail: `TCP connect to ${host}:${r.port} succeeded in ${r.rttMs}ms. Public exposure of this service is often unintentional on a web asset.`,
      remediation: "Confirm the service should be internet-facing; restrict with firewall or bind to private networks if not required.",
      evidence: `host=${host} port=${r.port} state=open rttMs=${r.rttMs} probedAt=${r.probedAt}`,
      url: `${host}:${r.port}`,
      owasp: "A05:2021 Security Misconfiguration",
      cwe: "CWE-200",
    });
  }

  notes.push(
    `Port probe complete: ${open.length} open / ${results.length} probed on ${host} (TCP connect, ${timeoutMs}ms timeout).`,
  );

  return { results, findings, notes };
}

export function portChangeFindings(
  host: string,
  previousOpen: number[] | null | undefined,
  current: PortProbeResult[],
): ScanFinding[] {
  if (!previousOpen?.length) return [];
  const prev = new Set(previousOpen);
  const now = new Set(current.filter((r) => r.state === "open").map((r) => r.port));
  const added = [...now].filter((p) => !prev.has(p));
  const removed = [...prev].filter((p) => !now.has(p));
  const findings: ScanFinding[] = [];
  if (added.length) {
    findings.push({
      id: "port-set-expanded",
      category: "PORTS",
      risk: "medium",
      title: "New open ports since baseline",
      detail: `Open port set grew by ${added.length}: ${added.join(", ")}.`,
      remediation: "Verify new listeners are intentional and authorized.",
      evidence: `host=${host} added=${added.join(",")} previous=${[...prev].join(",")}`,
    });
  }
  if (removed.length) {
    findings.push({
      id: "port-set-shrunk",
      category: "PORTS",
      risk: "info",
      title: "Open ports closed since baseline",
      detail: `Previously open ports no longer accept TCP connects: ${removed.join(", ")}.`,
      remediation: "Confirm expected decommissioning of services.",
      evidence: `host=${host} removed=${removed.join(",")}`,
    });
  }
  return findings;
}
