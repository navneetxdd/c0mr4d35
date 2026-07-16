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

  const hardTimeout = opts.timeoutMs ?? DEFAULT_TIMEOUT;
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;

  return new Promise((resolve, reject) => {
    const transport = isHttps ? https : http;
    let settled = false;
    // eslint-disable-next-line prefer-const -- forward-referenced by done()/killer before assignment
    let req: http.ClientRequest | undefined;

    // Single settlement path. Crucially, the deadline calls done() DIRECTLY —
    // it never waits for a socket 'error' event, which a tarpitting target can
    // withhold indefinitely. The socket is torn down for cleanup, but the
    // promise resolves/rejects regardless of whether Node emits an event.
    const done = (err: Error | null, value?: FetchResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(killer);
      try {
        req?.destroy();
      } catch {
        // ignore
      }
      if (err) reject(err);
      else resolve(value!);
    };

    const killer = setTimeout(() => done(new Error("Request deadline exceeded")), hardTimeout);

    req = transport.request(
      {
        hostname: opts.pin.address,
        port,
        path,
        method: opts.method ?? "GET",
        headers: {
          host: opts.pin.hostname,
          "user-agent": USER_AGENT,
          accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          connection: "close",
          ...opts.headers,
        },
        // Pin connect to the validated IP — never re-resolve DNS.
        lookup: (_hostname, _options, cb) => {
          cb(null, opts.pin.address, opts.pin.family);
        },
        servername: isHttps ? opts.pin.hostname : undefined,
        agent: false, // no pooling — each probe is an isolated, disposable socket
        timeout: hardTimeout,
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
        const emit = () =>
          done(null, {
            status,
            headers,
            body: Buffer.concat(chunks).toString("utf8"),
            finalUrl: target,
            redirectedTo,
            elapsedMs: Date.now() - started,
          });

        res.on("data", (chunk: Buffer) => {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          if (received + buf.byteLength > maxBytes) {
            chunks.push(buf.subarray(0, Math.max(0, maxBytes - received)));
            received = maxBytes;
            emit(); // enough — settle and tear down
            return;
          }
          chunks.push(buf);
          received += buf.byteLength;
        });
        res.on("end", emit);
        res.on("close", emit);
        res.on("aborted", () => done(new Error("Response aborted")));
        res.on("error", (err) => done(err));
      },
    );

    req.on("timeout", () => done(new Error("Request timed out")));
    req.on("error", (err) => done(err));
    try {
      req.setNoDelay(true);
    } catch {
      // ignore
    }
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
