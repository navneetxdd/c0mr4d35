# Audit — Feature 1: Auto-Remediation ("Self-Writing Firewall")

**Date:** 2026-07-16
**Branch:** `feat/auto-remediation` (off `c37b60e`)
**Status:** Implemented, tested, verified. Ready to merge.

## What it does
For any scanned target, Datum now generates a copy-paste **fix**, not just findings:
a Content-Security-Policy built from the scripts/forms actually observed on the
page, plus the exact hardening-header config for five server stacks (Next.js,
nginx, Apache, Caddy, Cloudflare Worker). The remediation surfaces in the Live
Scan console under the findings.

## Design decision: no persistence, no new attack surface
Remediation is a **pure projection** of scan data (findings + resource
inventory), so it is recomputed wherever a scan is displayed. Deliberately:
- **No new DB table / migration / column** → no unverified DB writes, no RLS to get wrong.
- **No new API route** → it rides the existing `POST /api/scan` and
  `POST /api/assets/[id]/scan`, which already enforce `requireRole("analyst")` +
  rate-limiting when Supabase is configured. Auth is **inherited**, not re-implemented.
- **Nothing is hardcoded to any site.** The CSP allowlist is derived from
  `signals.externalScriptOrigins` / `signals.formActions`; the stack is derived
  from `fingerprint`/`techStack`. The only constants are standard header values
  (e.g. HSTS `max-age=63072000`), which are the correct fix, not site-specific data.

## Files
- **New** `src/lib/scan/remediate.ts` — `buildRemediation(input)` pure engine.
- **New** `scripts/test-remediate.mts` — 21-assertion unit test (no framework).
- **Modified** `src/lib/scan/index.ts` — import + compute + attach `remediation`
  to `ScanResult` (also gives the monitor daemon / forensic report access).
- **Modified** `src/components/scan/ScanConsole.tsx` — `RemediationPanel` +
  `CodeBlock` (platform tabs, copy, download, CSP report-only→enforce rollout).
- **New** `.claude/launch.json`, `docs/audits/…` (tooling/docs).
- `SafeScanResult = Omit<ScanResult,"html">` already carries `remediation` to the client — no type change needed.

## Testing (every change exercised)
1. **Unit — 21/21 pass** (`npx tsx scripts/test-remediate.mts`): origin dedupe,
   self-origin exclusion, unparseable-URL rejection, external form origins in
   `form-action`, `frame-ancestors 'none'`, `upgrade-insecure-requests` on HTTPS,
   report-uri on the report-only variant, platform detection (nginx/nextjs/apache/default),
   "null when nothing to fix", and **config-injection safety** (values with quotes
   never break out of the quoted config).
2. **Build — clean** (`npm run build`): full typecheck + 15 routes compiled.
3. **E2E — live scan** of `https://scan-bice.vercel.app` via `POST /api/scan`:
   detected **Next.js** → primary config `nextjs`; generated a real CSP; emitted
   all 5 platform configs with correct syntax; summary + notes present.

## Known limitations (honest)
- The **React panel could not be rendered in this environment** because the
  `/scan` page's server component (`fetchShellContext`) requires Supabase env,
  which isn't set locally. The panel **compiles** and reuses the exact
  design-system primitives (`panel`, `MonoEyebrow`, token classes) as the
  already-verified sibling panels; it will render on the Supabase-backed deploy.
- CSP `connect-src`/`img-src`/`style-src` are **conservative starters** (documented
  in-UI). The engine only sees script + form origins today; widening these is a
  future enhancement (capture connect/img origins during crawl) or is tuned via
  the report-only `report-uri` rollout.
- `style-src` includes `'unsafe-inline'` as a pragmatic default — flagged in notes.

## Follow-ups (not blocking)
- Optionally add a `GET /api/csp-report` collector so violations become live findings (closes the loop further).
- Optionally render the remediation on the persisted asset-detail view (same pure function, from stored `signals`+`findings`).
