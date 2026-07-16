import type { AppRole } from "@/lib/supabase/types";
import type { Posture, Telemetry } from "@/lib/types";

export interface ShellContext {
  posture: Posture;
  watchCount: number;
  telemetry: Telemetry;
  profile: { email: string; role: AppRole } | null;
  isAdmin: boolean;
  isAnalyst: boolean;
}
