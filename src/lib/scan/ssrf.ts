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

function hextetsToIpv4(hi: string, lo: string): string | null {
  const h = Number.parseInt(hi, 16);
  const l = Number.parseInt(lo, 16);
  if (!Number.isFinite(h) || !Number.isFinite(l) || h < 0 || l < 0 || h > 0xffff || l > 0xffff) {
    return null;
  }
  return `${(h >> 8) & 255}.${h & 255}.${(l >> 8) & 255}.${l & 255}`;
}

/** Expand a sparse IPv6 literal to 8 hextets (best-effort). */
function expandIpv6(address: string): string[] | null {
  const raw = address.toLowerCase().split("%")[0]?.replace(/^\[|\]$/g, "") ?? "";
  if (!raw.includes(":")) return null;
  const [head, tail] = raw.split("::");
  const headParts = head ? head.split(":").filter(Boolean) : [];
  const tailParts = tail ? tail.split(":").filter(Boolean) : [];
  if (raw.includes("::")) {
    const missing = 8 - headParts.length - tailParts.length;
    if (missing < 0) return null;
    return [...headParts, ...Array(missing).fill("0"), ...tailParts];
  }
  const parts = raw.split(":");
  return parts.length === 8 ? parts : null;
}

/**
 * Pull an embedded IPv4 out of IPv4-mapped, NAT64, or 6to4 forms.
 * Dotted (::ffff:127.0.0.1) and hex (::ffff:7f00:1) both matter — attackers
 * use the hex form to bypass naive dotted-only checks.
 */
function embeddedIpv4FromIpv6(address: string): string | null {
  const addr = address.toLowerCase().split("%")[0]?.replace(/^\[|\]$/g, "") ?? "";

  // IPv4-mapped :ffff:a.b.c.d
  const dotted = addr.match(/:ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (dotted?.[1]) return dotted[1];

  // IPv4-mapped hex :ffff:7f00:1
  const hexMapped = addr.match(/:ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (hexMapped?.[1] && hexMapped[2]) return hextetsToIpv4(hexMapped[1], hexMapped[2]);

  // Deprecated IPv4-compatible ::a.b.c.d (e.g. [::127.0.0.1]) — no ffff marker
  const compatDotted = addr.match(/^::(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (compatDotted?.[1]) return compatDotted[1];

  // 6to4 2002:V4:/48 — next 32 bits are the IPv4
  const sixToFour = addr.match(/^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4})/i);
  if (sixToFour?.[1] && sixToFour[2]) return hextetsToIpv4(sixToFour[1], sixToFour[2]);

  // NAT64 well-known prefix 64:ff9b::/96 — last 32 bits are IPv4
  if (addr.startsWith("64:ff9b:") || addr.startsWith("64:ff9b::")) {
    const parts = expandIpv6(addr);
    if (parts && parts.length === 8) {
      return hextetsToIpv4(parts[6]!, parts[7]!);
    }
  }

  // Deprecated IPv4-compatible hex ::7f00:1 (96-bit zero prefix, last 32 = IPv4)
  const parts = expandIpv6(addr);
  if (parts && parts.length === 8) {
    const highZero = parts.slice(0, 5).every((p) => Number.parseInt(p, 16) === 0);
    const fifth = Number.parseInt(parts[5]!, 16);
    // Mapped uses hextet 5 = 0xffff; compatible uses 0
    if (highZero && fifth === 0) {
      return hextetsToIpv4(parts[6]!, parts[7]!);
    }
  }

  return null;
}

function isPublicIpv6(address: string): boolean {
  const addr = address.toLowerCase().split("%")[0]?.replace(/^\[|\]$/g, "") ?? "";
  if (addr === "::1" || addr === "::") return false; // loopback / unspecified
  // fe80::/10 link-local (fe80–febf)
  if (/^fe[89ab][0-9a-f]:/i.test(addr) || addr.startsWith("fe80:")) return false;
  // fec0::/10 deprecated site-local (fec0–feff)
  if (/^fe[cdef][0-9a-f]:/i.test(addr)) return false;
  // fc00::/7 unique-local
  if (/^f[cd][0-9a-f]{2}:/i.test(addr)) return false;
  // ff00::/8 multicast
  if (/^ff[0-9a-f]{2}:/i.test(addr)) return false;

  const embedded = embeddedIpv4FromIpv6(addr);
  if (embedded) return isPublicIpv4(embedded);

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

  // Literal IPs (and IPv6 forms Node's isIP may miss). Never DNS-lookup colon hosts.
  const literalKind = isIP(hostname);
  if (literalKind || hostname.includes(":")) {
    const addr = hostname.replace(/^\[|\]$/g, "");
    const embedded = embeddedIpv4FromIpv6(addr);
    if (embedded && !isPublicIpv4(embedded)) {
      throw new SsrfError("Target resolves to a non-public address");
    }
    if (literalKind && isPublicAddress(addr)) {
      return {
        url,
        hostname,
        address: addr,
        family: literalKind === 6 ? 6 : 4,
      };
    }
    throw new SsrfError("Target resolves to a non-public address");
  }

  let records: { address: string; family: number }[];
  try {
    records = await Promise.race([
      dnsLookup(hostname, { all: true }),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("dns-timeout")), 5000)),
    ]);
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
