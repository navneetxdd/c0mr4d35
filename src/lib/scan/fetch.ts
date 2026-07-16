import http from "node:http";
import https from "node:https";
import type { ResolvedTarget } from "./ssrf";

/**
 * Server-side fetch for the scanner using Node's native http/https modules.
 * Connections are pinned to the IP validated by resolveTarget() via a custom
 * lookup callback — no second DNS resolution at connect time, closing the
 * DNS-rebinding TOCTOU window. Avoids undici's dispatcher quirks on Windows.
 */

interface GuardedFetchOptions {
  method?: string;
  timeoutMs?: number;
  maxBytes?: number;
  headers?: Record<string, string>;
  /** Required pin from resolveTarget — connect only to this validated address. */
  pin: Pick<ResolvedTarget, "hostname" | "address" | "family">;
}

const DEFAULT_TIMEOUT = 12_000;
const DEFAULT_MAX_BYTES = 3_000_000;
const USER_AGENT = "DatumScanner/1.0 (+security-monitoring)";

export interface FetchResult {
  status: number;
  headers: Record<string, string>;
  body: string;
  finalUrl: string;
  redirectedTo: string | null;
  elapsedMs: number;
}

export function guardedFetch(target: string, opts: GuardedFetchOptions): Promise<FetchResult> {
  const started = Date.now();
  const url = new URL(target);
  const isHttps = url.protocol === "https:";
  const port = url.port ? Number(url.port) : isHttps ? 443 : 80;
  const path = `${url.pathname}${url.search}`;

  return new Promise((resolve, reject) => {
    const transport = isHttps ? https : http;
    const req = transport.request(
      {
        hostname: opts.pin.address,
        port,
        path,
        method: opts.method ?? "GET",
        headers: {
          host: opts.pin.hostname,
          "user-agent": USER_AGENT,
          accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          ...opts.headers,
        },
        // Pin connect to the validated IP — never re-resolve DNS.
        lookup: (_hostname, _options, cb) => {
          cb(null, opts.pin.address, opts.pin.family);
        },
        servername: isHttps ? opts.pin.hostname : undefined,
        timeout: opts.timeoutMs ?? DEFAULT_TIMEOUT,
      },
      (res) => {
        const headers: Record<string, string> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (value === undefined) continue;
          headers[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : String(value);
        }

        const location = headers["location"] ?? null;
        const status = res.statusCode ?? 0;
        const redirectedTo =
          status >= 300 && status < 400 && location ? safeResolve(location, target) : null;

        const chunks: Buffer[] = [];
        let received = 0;
        const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;

        res.on("data", (chunk: Buffer) => {
          if (received >= maxBytes) return;
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          if (received + buf.byteLength > maxBytes) {
            chunks.push(buf.subarray(0, maxBytes - received));
            received = maxBytes;
            res.destroy();
            return;
          }
          chunks.push(buf);
          received += buf.byteLength;
        });

        res.on("end", () => {
          resolve({
            status,
            headers,
            body: Buffer.concat(chunks).toString("utf8"),
            finalUrl: target,
            redirectedTo,
            elapsedMs: Date.now() - started,
          });
        });

        res.on("error", reject);
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error("Request timed out"));
    });
    req.on("error", reject);
    req.end();
  });
}

function safeResolve(location: string, base: string): string | null {
  try {
    return new URL(location, base).toString();
  } catch {
    return null;
  }
}
