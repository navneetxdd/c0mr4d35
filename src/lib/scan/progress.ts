export type ScanStageId =
  | "resolve"
  | "fetch"
  | "crawl"
  | "headers_tls_dns"
  | "paths_cors"
  | "screenshot_diff"
  | "ports"
  | "subdomains"
  | "persist_ai"
  | "done"
  | "error";

export interface ScanStageEvent {
  stage: ScanStageId;
  pct: number;
  message: string;
  artifact?: string | null;
  at: string;
}

/** Cumulative weights — each stage reports its end percentage when complete. */
export const STAGE_PCT: Record<ScanStageId, number> = {
  resolve: 5,
  fetch: 15,
  crawl: 30,
  headers_tls_dns: 45,
  paths_cors: 55,
  screenshot_diff: 75,
  ports: 85,
  subdomains: 95,
  persist_ai: 98,
  done: 100,
  error: 100,
};

export type ProgressSink = (event: ScanStageEvent) => void | Promise<void>;

export function createProgress(onStage?: ProgressSink) {
  return async function report(
    stage: ScanStageId,
    message: string,
    artifact?: string | null,
  ): Promise<void> {
    if (!onStage) return;
    await onStage({
      stage,
      pct: STAGE_PCT[stage],
      message,
      artifact: artifact ?? null,
      at: new Date().toISOString(),
    });
  };
}
