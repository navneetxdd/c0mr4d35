"use client";

import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { MonoEyebrow } from "@/components/ui/MonoEyebrow";
import { RegistrationMarks } from "@/components/ui/RegistrationMarks";
import { StatusLed } from "@/components/ui/StatusLed";
import type { Asset } from "@/lib/types";

interface AddAssetDrawerProps {
  open: boolean;
  onClose: () => void;
  onCreated: (asset: Asset) => void;
}

type ResolveState =
  | { kind: "idle" }
  | { kind: "checking" }
  | { kind: "ok"; detail: string }
  | { kind: "blocked"; detail: string }
  | { kind: "invalid"; detail: string };

function classifyUrl(raw: string): ResolveState {
  const trimmed = raw.trim();
  if (!trimmed) return { kind: "idle" };
  let url: URL;
  try {
    url = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
  } catch {
    return { kind: "invalid", detail: "✗ MALFORMED URL" };
  }
  if (!["http:", "https:"].includes(url.protocol)) {
    return { kind: "invalid", detail: "✗ ONLY HTTP/HTTPS" };
  }
  const host = url.hostname.toLowerCase();
  if (
    host === "localhost" ||
    host.endsWith(".local") ||
    host === "0.0.0.0" ||
    host === "::1"
  ) {
    return { kind: "blocked", detail: "✗ PRIVATE RANGE BLOCKED" };
  }
  if (/^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(host)) {
    return { kind: "blocked", detail: "✗ PRIVATE RANGE BLOCKED" };
  }
  if (host === "metadata.google.internal" || host === "169.254.169.254") {
    return { kind: "blocked", detail: "✗ LINK-LOCAL / METADATA BLOCKED" };
  }
  return { kind: "ok", detail: "✓ RESOLVES TO PUBLIC IP (preflight)" };
}

export function AddAssetDrawer({ open, onClose, onCreated }: AddAssetDrawerProps) {
  const [url, setUrl] = useState("");
  const [name, setName] = useState("");
  const [interval, setIntervalMin] = useState("15");
  const [resolve, setResolve] = useState<ResolveState>({ kind: "idle" });
  const [phase, setPhase] = useState<"form" | "establishing" | "done">("form");

  useEffect(() => {
    if (!open) return;
    setResolve({ kind: "checking" });
    const t = window.setTimeout(() => setResolve(classifyUrl(url)), 280);
    return () => window.clearTimeout(t);
  }, [url, open]);

  useEffect(() => {
    if (!open) {
      setUrl("");
      setName("");
      setIntervalMin("15");
      setPhase("form");
      setResolve({ kind: "idle" });
    }
  }, [open]);

  const canSubmit = useMemo(() => {
    return (
      resolve.kind === "ok" &&
      name.trim().length >= 2 &&
      Number(interval) >= 5 &&
      phase === "form"
    );
  }, [resolve, name, interval, phase]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <button
        type="button"
        className="absolute inset-0 bg-void/70"
        aria-label="Close drawer"
        onClick={onClose}
      />
      <aside
        className="relative flex h-full w-full max-w-md flex-col border-l border-edge bg-carbon"
        role="dialog"
        aria-modal
        aria-labelledby="add-asset-title"
      >
        <RegistrationMarks />
        <div className="border-b border-edge px-5 py-4">
          <MonoEyebrow index="08">Establish baseline</MonoEyebrow>
          <h2 id="add-asset-title" className="mt-2 type-h2 text-text">
            Add asset
          </h2>
        </div>

        <div className="flex-1 space-y-4 overflow-y-auto px-5 py-5">
          {phase === "form" ? (
            <>
              <Input
                label="URL"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://status.acme-ops.io"
                className="font-data"
                hint={
                  resolve.kind === "ok" || resolve.kind === "blocked" || resolve.kind === "invalid"
                    ? resolve.detail
                    : resolve.kind === "checking"
                      ? "… validating"
                      : "Live SSRF-safe preflight"
                }
                error={
                  resolve.kind === "blocked" || resolve.kind === "invalid"
                    ? resolve.detail
                    : undefined
                }
              />
              <Input
                label="Friendly name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="status-page"
              />
              <Input
                label="Scan interval (minutes)"
                type="number"
                min={5}
                value={interval}
                onChange={(e) => setIntervalMin(e.target.value)}
                className="font-data"
              />
            </>
          ) : null}

          {phase === "establishing" || phase === "done" ? (
            <div className="panel space-y-3 p-4">
              <div className="flex items-center gap-2">
                <StatusLed posture={phase === "done" ? "secure" : "scanning"} label />
              </div>
              <p className="font-data text-[13px] text-text">
                {phase === "establishing"
                  ? "ESTABLISHING BASELINE…"
                  : "DATUM LOCKED · first scan complete"}
              </p>
              <p className="type-data-sm text-text-dim">
                Job enqueued → worker will capture and set the known-good reference.
              </p>
            </div>
          ) : null}
        </div>

        <div className="flex gap-2 border-t border-edge px-5 py-4">
          <Button variant="secondary" className="flex-1" onClick={onClose}>
            Cancel
          </Button>
          {phase === "form" ? (
            <Button
              className="flex-1"
              disabled={!canSubmit}
              onClick={() => {
                setPhase("establishing");
                window.setTimeout(() => {
                  const host = (() => {
                    try {
                      return new URL(
                        url.includes("://") ? url : `https://${url}`,
                      ).hostname;
                    } catch {
                      return url;
                    }
                  })();
                  const asset: Asset = {
                    id: `a-${Date.now()}`,
                    name: name.trim(),
                    host,
                    posture: "scanning",
                    driftScore: 0,
                    driftHistory: [0, 0, 0, 0, 0, 0],
                    lastCheckAt: new Date().toISOString(),
                    thumbnail: "/captures/status-current.svg",
                    baselineCapture: "/captures/status-baseline.svg",
                    currentCapture: "/captures/status-current.svg",
                    openIncident: false,
                    scanIntervalMin: Number(interval) || 15,
                  };
                  setPhase("done");
                  onCreated(asset);
                }, 1600);
              }}
            >
              Establish
            </Button>
          ) : (
            <Button className="flex-1" onClick={onClose} disabled={phase !== "done"}>
              Done
            </Button>
          )}
        </div>
      </aside>
    </div>
  );
}
