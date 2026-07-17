"use client";

import React, { useState, useMemo } from "react";
import { cn } from "@/lib/format";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";

export interface SurfaceMapData {
  finalHost: string;
  posture: string;
  postureScore: number;
  findings: Array<{
    id: string;
    category: string;
    risk: string;
    title: string;
    detail: string;
    remediation: string;
    evidence?: string | null;
  }>;
  ports?: Array<{ port: number; state: string; rttMs: number; probedAt: string }>;
  subdomains?: Array<{ subdomain: string; source: string; ips: string[]; queriedAt: string }>;
}

interface SurfaceMapProps {
  data: SurfaceMapData;
}

interface GraphNode {
  id: string;
  label: string;
  type: "center" | "subdomain" | "port" | "cve";
  x: number;
  y: number;
  r: number;
  color: string;
  detail: string;
  evidence?: string;
}

interface GraphLink {
  from: GraphNode;
  to: GraphNode;
  color: string;
  dashed?: boolean;
}

// SVG Graph Layout Math
export function SurfaceMap({ data }: SurfaceMapProps) {
  const [activeTab, setActiveTab] = useState<"graph" | "table">("graph");
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const openPorts = useMemo(() => {
    return (data.ports ?? []).filter((p) => p.state === "open" || p.state === "OPEN");
  }, [data.ports]);

  const subs = useMemo(() => {
    return data.subdomains ?? [];
  }, [data.subdomains]);

  const cves = useMemo(() => {
    return data.findings.filter((f) => f.category === "CVE");
  }, [data.findings]);

  // SVG Graph Layout Math
  const graphData = useMemo(() => {
    const width = 640;
    const height = 480;
    const centerX = width / 2;
    const centerY = height / 2;

    const nodes: GraphNode[] = [];
    const links: GraphLink[] = [];

    // 1. Center Node (Apex Domain)
    const centerNode: GraphNode = {
      id: "apex",
      label: data.finalHost,
      type: "center",
      x: centerX,
      y: centerY,
      r: 22,
      color: "var(--live)",
      detail: `Target Apex Host: ${data.finalHost}\nStatus: ${data.posture.toUpperCase()}\nScore: ${Math.round(data.postureScore)}/100`,
    };
    nodes.push(centerNode);

    // Limit subdomain rendering so the SVG remains readable
    const maxSubdomainsToShow = 12;
    const slicedSubs = subs.slice(0, maxSubdomainsToShow);
    const subCount = slicedSubs.length;

    // 2. Subdomain Nodes (Radially around Center)
    slicedSubs.forEach((sub, i) => {
      const angle = (2 * Math.PI * i) / (subCount || 1);
      const radius = 135;
      const x = centerX + radius * Math.cos(angle);
      const y = centerY + radius * Math.sin(angle);
      const subId = `sub-${sub.subdomain}`;

      const node: GraphNode = {
        id: subId,
        label: sub.subdomain,
        type: "subdomain",
        x,
        y,
        r: 11,
        color: "var(--scan)",
        detail: `Subdomain: ${sub.subdomain}\nSource: ${sub.source.toUpperCase()}\nResolved IPs: ${sub.ips.join(", ") || "none"}`,
      };
      nodes.push(node);
      links.push({ from: centerNode, to: node, color: "var(--edge-hi)", dashed: true });
    });

    // 3. Open Port Nodes (Radially around Center or clustered)
    const portCount = openPorts.length;
    openPorts.forEach((port, i) => {
      const angle = (2 * Math.PI * i) / (portCount || 1) + Math.PI / 6;
      const radius = 80;
      const x = centerX + radius * Math.cos(angle);
      const y = centerY + radius * Math.sin(angle);
      const portId = `port-${port.port}`;

      const isRisky = [22, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017].includes(port.port);

      const node: GraphNode = {
        id: portId,
        label: `:${port.port}`,
        type: "port",
        x,
        y,
        r: 9,
        color: isRisky ? "var(--critical)" : "var(--secure)",
        detail: `Port: ${port.port}\nState: OPEN\nSource: ${port.rttMs === 0 ? "Shodan/InternetDB index" : `TCP Connect (${port.rttMs}ms)`}\nSeen At: ${port.probedAt}`,
      };
      nodes.push(node);
      links.push({ from: centerNode, to: node, color: "rgba(184, 240, 76, 0.2)" });

      // 4. CVE Nodes branching from ports
      cves.forEach((cve, cIndex) => {
        const evidenceStr = cve.evidence ?? "";
        if (evidenceStr.includes(String(port.port)) && cIndex < 3) {
          const cveAngle = angle + (cIndex - 1) * 0.35;
          const cveRadius = radius + 35;
          const cveX = centerX + cveRadius * Math.cos(cveAngle);
          const cveY = centerY + cveRadius * Math.sin(cveAngle);
          const cveNode: GraphNode = {
            id: `cve-${cve.id}`,
            label: cve.title.split(" ").pop() ?? "CVE",
            type: "cve",
            x: cveX,
            y: cveY,
            r: 7,
            color: "var(--critical)",
            detail: `Vulnerability: ${cve.title}\nDetail: ${cve.detail}\nRemediation: ${cve.remediation}`,
            evidence: cve.evidence ?? undefined,
          };
          nodes.push(cveNode);
          links.push({ from: node, to: cveNode, color: "rgba(240, 86, 63, 0.3)" });
        }
      });
    });

    // Directly attach leftover CVEs
    const mappedCves = new Set(nodes.filter(n => n.type === "cve").map(n => n.id));
    cves.forEach((cve, i) => {
      const cveId = `cve-${cve.id}`;
      if (!mappedCves.has(cveId) && i < 6) {
        const angle = (2 * Math.PI * i) / 6 - Math.PI / 2;
        const radius = 175;
        const x = centerX + radius * Math.cos(angle);
        const y = centerY + radius * Math.sin(angle);

        const cveNode: GraphNode = {
          id: cveId,
          label: cve.title.includes("CVE") ? cve.title.match(/CVE-\d{4}-\d+/)?.[0] ?? "CVE" : "VULN",
          type: "cve",
          x,
          y,
          r: 7,
          color: "var(--critical)",
          detail: `Vulnerability: ${cve.title}\nDetail: ${cve.detail}\nRemediation: ${cve.remediation}`,
          evidence: cve.evidence ?? undefined,
        };
        nodes.push(cveNode);
        links.push({ from: centerNode, to: cveNode, color: "rgba(240, 86, 63, 0.25)" });
      }
    });

    return { nodes, links, width, height };
  }, [data.finalHost, data.posture, data.postureScore, openPorts, subs, cves]);

  return (
    <section className="panel relative p-4 stagger-in">
      <RegistrationMarks />
      <div className="flex items-center justify-between border-b border-edge pb-3">
        <div className="flex items-center gap-2">
          <span className="h-1.5 w-1.5 rounded-full bg-live led-critical" />
          <span className="font-display text-[14px] font-bold uppercase tracking-wider text-text">
            02 · Passive Attack Surface Map
          </span>
        </div>
        <div className="flex rounded-sm bg-void/50 p-0.5 border border-edge">
          <button
            onClick={() => setActiveTab("graph")}
            className={cn(
              "rounded-sm px-3 py-1 font-data text-[11px] transition-colors cursor-pointer",
              activeTab === "graph"
                ? "bg-slate text-text"
                : "text-text-faint hover:text-text-dim"
            )}
          >
            GRAPH MAP
          </button>
          <button
            onClick={() => setActiveTab("table")}
            className={cn(
              "rounded-sm px-3 py-1 font-data text-[11px] transition-colors cursor-pointer",
              activeTab === "table"
                ? "bg-slate text-text"
                : "text-text-faint hover:text-text-dim"
            )}
          >
            DATA LEDGER
          </button>
        </div>
      </div>

      {activeTab === "graph" ? (
        <div className="mt-4 grid gap-4 lg:grid-cols-[1fr_260px]">
          <div className="relative flex items-center justify-center rounded-sm border border-edge bg-void/40 overflow-hidden">
            <svg
              viewBox={`0 0 ${graphData.width} ${graphData.height}`}
              className="w-full max-h-[460px] select-none"
            >
              <defs>
                <radialGradient id="glowGrad" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="var(--live)" stopOpacity="0.15" />
                  <stop offset="100%" stopColor="var(--live)" stopOpacity="0" />
                </radialGradient>
              </defs>

              <circle cx={graphData.width / 2} cy={graphData.height / 2} r="75" fill="none" stroke="var(--edge)" strokeWidth="1" strokeDasharray="4,4" />
              <circle cx={graphData.width / 2} cy={graphData.height / 2} r="120" fill="none" stroke="var(--edge)" strokeWidth="1" strokeDasharray="6,6" />
              <circle cx={graphData.width / 2} cy={graphData.height / 2} r="175" fill="none" stroke="var(--edge)" strokeWidth="1" strokeDasharray="8,8" />

              {graphData.links.map((link, idx) => (
                <line
                  key={idx}
                  x1={link.from.x}
                  y1={link.from.y}
                  x2={link.to.x}
                  y2={link.to.y}
                  stroke={link.color}
                  strokeWidth="1.5"
                  strokeDasharray={link.dashed ? "3,3" : undefined}
                />
              ))}

              <circle
                cx={graphData.width / 2}
                cy={graphData.height / 2}
                r="45"
                fill="url(#glowGrad)"
              />

              {graphData.nodes.map((node) => {
                const isActive = selectedNode?.id === node.id;
                return (
                  <g
                    key={node.id}
                    className="cursor-pointer group"
                    onClick={() => setSelectedNode(node)}
                  >
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={node.r}
                      fill={isActive ? "var(--text)" : "var(--slate)"}
                      stroke={node.color}
                      strokeWidth={isActive ? "3" : "2"}
                      className="transition-all duration-150 group-hover:scale-110"
                    />
                    {node.type === "center" && (
                      <circle
                        cx={node.x}
                        cy={node.y}
                        r={node.r + 6}
                        fill="none"
                        stroke={node.color}
                        strokeWidth="1"
                        strokeDasharray="2,2"
                        className="animate-pulse"
                      />
                    )}
                    <text
                      x={node.x}
                      y={node.y + node.r + 14}
                      textAnchor="middle"
                      fill={isActive ? "var(--text)" : "var(--text-dim)"}
                      className="font-data text-[9px] font-medium pointer-events-none group-hover:fill-text"
                    >
                      {node.label.length > 20 ? node.label.slice(0, 18) + "..." : node.label}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          <div className="rounded-sm border border-edge bg-void/25 p-3 flex flex-col justify-between min-h-[300px]">
            <div>
              <p className="type-label mb-3">NODE INSPECTOR</p>
              {selectedNode ? (
                <div className="space-y-3 stagger-in">
                  <div className="flex items-center gap-2">
                    <span
                      className="h-2 w-2 rounded-full"
                      style={{ backgroundColor: selectedNode.color }}
                    />
                    <span className="font-data text-[12px] font-bold text-text truncate">
                      {selectedNode.label}
                    </span>
                  </div>
                  <div className="rounded-sm border border-edge bg-void/50 p-2.5">
                    <pre className="whitespace-pre-wrap font-data text-[11px] leading-relaxed text-text-dim">
                      {selectedNode.detail}
                    </pre>
                  </div>
                  {selectedNode.evidence && (
                    <div className="space-y-1">
                      <span className="type-data-sm text-text-faint">Evidence Proof</span>
                      <div className="rounded-sm border border-edge bg-void/50 p-2">
                        <code className="font-data text-[10px] text-text-faint break-all">
                          {selectedNode.evidence}
                        </code>
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <span className="text-[20px] text-text-faint">📡</span>
                  <p className="mt-2 font-data text-[11px] text-text-faint">
                    Click any node in the map graph to inspect its network parameters and properties.
                  </p>
                </div>
              )}
            </div>

            <div className="border-t border-edge pt-3 mt-4">
              <div className="flex flex-wrap gap-x-4 gap-y-2 font-data text-[10px] text-text-faint">
                <div className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-live" /> Apex Host
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-scan" /> Subdomain
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-secure" /> Safe Port
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-critical" /> Risk/CVE
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          <div className="overflow-auto rounded-sm border border-edge bg-void/20">
            <p className="border-b border-edge px-3 py-2 type-label">Subdomains ({subs.length})</p>
            {subs.length ? (
              <table className="w-full text-left font-data text-[11px]">
                <thead className="text-text-faint">
                  <tr>
                    <th className="px-3 py-1.5">NAME</th>
                    <th className="px-3 py-1.5">SOURCE</th>
                    <th className="px-3 py-1.5">IPS</th>
                  </tr>
                </thead>
                <tbody>
                  {subs.slice(0, 30).map((s) => (
                    <tr key={s.subdomain} className="border-t border-edge hover:bg-void/40">
                      <td className="px-3 py-1.5 text-text font-medium">{s.subdomain}</td>
                      <td className="px-3 py-1.5 text-text">{s.source}</td>
                      <td className="px-3 py-1.5 text-text-faint">{s.ips.join(", ") || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="px-3 py-4 font-data text-[11px] text-text-faint">No subdomains discovered.</p>
            )}
          </div>

          <div className="flex flex-col gap-4">
            <div className="overflow-auto rounded-sm border border-edge bg-void/20">
              <p className="border-b border-edge px-3 py-2 type-label">Open ports ({openPorts.length})</p>
              {openPorts.length ? (
                <table className="w-full text-left font-data text-[11px]">
                  <thead className="text-text-faint">
                    <tr>
                      <th className="px-3 py-1.5">PORT</th>
                      <th className="px-3 py-1.5">SOURCE</th>
                      <th className="px-3 py-1.5">SEEN</th>
                    </tr>
                  </thead>
                  <tbody>
                    {openPorts.map((p) => (
                      <tr key={p.port} className="border-t border-edge hover:bg-void/40">
                        <td className="px-3 py-1.5 text-text font-medium">{p.port}</td>
                        <td className="px-3 py-1.5 text-text">
                          {p.rttMs === 0 ? "InternetDB/Shodan index" : `TCP ${p.rttMs}ms`}
                        </td>
                        <td className="px-3 py-1.5 text-text-faint">{p.probedAt}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="px-3 py-4 font-data text-[11px] text-text-faint">No open ports in probed set.</p>
              )}
            </div>

            <div className="overflow-auto rounded-sm border border-edge bg-void/20 flex-1">
              <p className="border-b border-edge px-3 py-2 type-label">CVE Vulnerabilities ({cves.length})</p>
              {cves.length ? (
                <table className="w-full text-left font-data text-[11px]">
                  <thead className="text-text-faint">
                    <tr>
                      <th className="px-3 py-1.5">ID</th>
                      <th className="px-3 py-1.5">TITLE</th>
                      <th className="px-3 py-1.5">RISK</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cves.map((c) => (
                      <tr key={c.id} className="border-t border-edge hover:bg-void/40">
                        <td className="px-3 py-1.5 text-text font-medium truncate max-w-[120px]">{c.id.split("-").slice(-2).join("-").toUpperCase()}</td>
                        <td className="px-3 py-1.5 text-text truncate max-w-[200px]" title={c.title}>{c.title}</td>
                        <td className="px-3 py-1.5 text-critical font-medium">{c.risk.toUpperCase()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="px-3 py-4 font-data text-[11px] text-text-faint">No CVEs mapped from threat feeds.</p>
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
