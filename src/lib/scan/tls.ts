import { connect as tlsConnect } from "node:tls";
import type { ScanFinding } from "./risk";

/**
 * TLS certificate posture: verifies a cert is presented and reports on
 * expiry proximity. Runs only for https targets.
 */

export interface TlsInfo {
  valid: boolean;
  daysToExpiry: number | null;
  issuer: string | null;
  subject: string | null;
  error?: string;
}

export function checkTls(hostname: string, port = 443, timeoutMs = 8000): Promise<TlsInfo> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (info: TlsInfo) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        // ignore
      }
      resolve(info);
    };

    const socket = tlsConnect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: false, // we inspect the cert ourselves; do not throw
        timeout: timeoutMs,
      },
      () => {
        const cert = socket.getPeerCertificate();
        if (!cert || Object.keys(cert).length === 0) {
          return done({ valid: false, daysToExpiry: null, issuer: null, subject: null, error: "No certificate presented" });
        }
        const expiry = cert.valid_to ? new Date(cert.valid_to).getTime() : null;
        const days = expiry ? Math.floor((expiry - Date.now()) / 86_400_000) : null;
        const first = (v: string | string[] | undefined): string | null =>
          Array.isArray(v) ? (v[0] ?? null) : (v ?? null);
        done({
          valid: socket.authorized,
          daysToExpiry: days,
          issuer: first(cert.issuer?.O) ?? first(cert.issuer?.CN),
          subject: first(cert.subject?.CN),
          error: socket.authorized ? undefined : socket.authorizationError?.toString(),
        });
      },
    );

    socket.on("error", (err) => done({ valid: false, daysToExpiry: null, issuer: null, subject: null, error: err.message }));
    socket.on("timeout", () => done({ valid: false, daysToExpiry: null, issuer: null, subject: null, error: "TLS handshake timed out" }));
  });
}

export function tlsFindings(info: TlsInfo): ScanFinding[] {
  const out: ScanFinding[] = [];
  if (info.error && info.daysToExpiry === null) {
    out.push({
      id: "tls-handshake",
      category: "TLS",
      risk: "medium",
      title: "TLS handshake could not be completed",
      detail: info.error,
      remediation: "Ensure a valid certificate chain is served on port 443.",
    });
    return out;
  }
  if (!info.valid) {
    out.push({
      id: "tls-invalid",
      category: "TLS",
      risk: "high",
      title: "Certificate chain does not validate",
      detail: info.error ?? "The presented certificate failed validation.",
      remediation: "Install a complete, trusted certificate chain.",
      evidence: info.issuer ? `Issuer: ${info.issuer}` : undefined,
    });
  }
  if (info.daysToExpiry !== null) {
    if (info.daysToExpiry < 0) {
      out.push({
        id: "tls-expired",
        category: "TLS",
        risk: "critical",
        title: "Certificate has expired",
        detail: `Expired ${Math.abs(info.daysToExpiry)} day(s) ago.`,
        remediation: "Renew and deploy the certificate immediately.",
      });
    } else if (info.daysToExpiry <= 14) {
      out.push({
        id: "tls-expiring",
        category: "TLS",
        risk: "medium",
        title: `Certificate expires in ${info.daysToExpiry} day(s)`,
        detail: "Certificate is inside the 14-day renewal window.",
        remediation: "Renew before expiry to avoid an outage.",
      });
    }
  }
  return out;
}
