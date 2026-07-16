import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";

/**
 * SSRF defense for the scanner. The scanner fetches arbitrary user-supplied
 * URLs, so it is the single most dangerous component in the product. Every
 * target must clear these gates before any bytes are fetched:
 *   1. Scheme allow-list (http/https only)
 *   2. No embedded credentials, no non-standard ports
 *   3. DNS resolves exclusively to public, routable unicast addresses
 * The resolved address is returned so the caller can pin the connection to the
 * exact IP that was validated, closing the DNS-rebinding TOCTOU window.
 */

export interface ResolvedTarget {
  url: URL;
  hostname: string;
  address: string;
  family: 4 | 6;
}

export class SsrfError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfError";
  }
}

const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);
const ALLOWED_PORTS = new Set(["", "80", "443", "8080", "8443"]);

function ipToBytes(address: string): number[] | null {
  const kind = isIP(address);
  if (kind === 4) {
    const parts = address.split(".").map((p) => Number(p));
    if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
      return null;
    }
    return parts;
  }
  return null;
}

/** Blocks loopback, private, link-local, CGNAT, and metadata ranges. */
export function isPublicIpv4(address: string): boolean {
  const b = ipToBytes(address);
  if (!b) return false;
  const [a, c, d] = b as [number, number, number, number];
  if (a === 0) return false; // "this network"
  if (a === 10) return false; // private
  if (a === 127) return false; // loopback
  if (a === 169 && c === 254) return false; // link-local + 169.254.169.254 metadata
  if (a === 172 && c >= 16 && c <= 31) return false; // private
  if (a === 192 && c === 168) return false; // private
  if (a === 100 && c >= 64 && c <= 127) return false; // CGNAT 100.64/10
  if (a === 192 && c === 0 && d === 0) return false; // IETF protocol assignments
  if (a === 198 && (c === 18 || c === 19)) return false; // benchmarking
  if (a >= 224) return false; // multicast + reserved (224+)
  return true;
}

function isPublicIpv6(address: string): boolean {
  const addr = address.toLowerCase().split("%")[0] ?? "";
  if (addr === "::1" || addr === "::") return false; // loopback / unspecified
  if (addr.startsWith("fe80")) return false; // link-local
  if (addr.startsWith("fc") || addr.startsWith("fd")) return false; // unique-local
  if (addr.startsWith("ff")) return false; // multicast
  // IPv4-mapped (::ffff:a.b.c.d) — validate the embedded v4 address.
  const mapped = addr.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped && mapped[1]) return isPublicIpv4(mapped[1]);
  return true;
}

export function isPublicAddress(address: string): boolean {
  const kind = isIP(address);
  if (kind === 4) return isPublicIpv4(address);
  if (kind === 6) return isPublicIpv6(address);
  return false;
}

/**
 * Validates a raw target string and resolves it to a single public IP.
 * Throws SsrfError with a safe, non-leaky message on any violation.
 */
export async function resolveTarget(raw: string): Promise<ResolvedTarget> {
  let url: URL;
  try {
    url = new URL(raw.includes("://") ? raw : `https://${raw}`);
  } catch {
    throw new SsrfError("Malformed URL");
  }

  if (!ALLOWED_PROTOCOLS.has(url.protocol)) {
    throw new SsrfError("Only http and https targets are allowed");
  }
  if (url.username || url.password) {
    throw new SsrfError("Credentials in URL are not allowed");
  }
  if (!ALLOWED_PORTS.has(url.port)) {
    throw new SsrfError("Target port is not allowed");
  }

  const hostname = url.hostname.toLowerCase();
  if (!hostname || hostname === "localhost" || hostname.endsWith(".local") || hostname.endsWith(".internal")) {
    throw new SsrfError("Target host is not permitted");
  }

  // If the host is a literal IP, validate directly.
  if (isIP(hostname)) {
    if (!isPublicAddress(hostname)) {
      throw new SsrfError("Target resolves to a non-public address");
    }
    return {
      url,
      hostname,
      address: hostname,
      family: isIP(hostname) === 6 ? 6 : 4,
    };
  }

  let records: { address: string; family: number }[];
  try {
    records = await dnsLookup(hostname, { all: true });
  } catch {
    throw new SsrfError("Target host could not be resolved");
  }

  if (!records.length) {
    throw new SsrfError("Target host could not be resolved");
  }

  // Every resolved record must be public — reject if any points inward.
  for (const rec of records) {
    if (!isPublicAddress(rec.address)) {
      throw new SsrfError("Target resolves to a non-public address");
    }
  }

  const pinned = records[0]!;
  return {
    url,
    hostname,
    address: pinned.address,
    family: pinned.family === 6 ? 6 : 4,
  };
}
