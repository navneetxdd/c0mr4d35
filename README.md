# Datum

**Website Defacement Detection & Vulnerability Assessment Platform** — System Siege PS-005 (Cyber Security & Web Mining).

Establish the truth of a web asset, then watch for the moment it stops being true. Datum baselines a site and continuously assesses it for defacement (content drift), missing security controls, TLS decay, exposed sensitive paths, and known stack advisories — prioritized by an AI verdict and surfaced through a role-based console with an audit trail.

## Features

The `/scan` console runs a live assessment against any public URL via `POST /api/scan`:

- **SSRF-guarded fetch** — scheme/port allow-list, credential rejection, DNS resolution to public IPs only, and a connect-time re-validation that defeats DNS-rebinding.
- **Defacement detection** — noise-normalized DOM canonicalization + SHA-256 hash and a token-level drift score against a baseline.
- **Security-header audit** — CSP, HSTS, X-Frame-Options / frame-ancestors, nosniff, Referrer-Policy, plus technology-disclosure hygiene.
- **TLS posture** — certificate validity and expiry-window checks.
- **Exposed-path probes** — `/.git/HEAD`, `/.env`, cloud-credential files, `security.txt`, gated on content signatures.
- **CVE correlation** — stack fingerprint → OSV.dev query (keyless).
- **AI verdict** — real findings prioritized and explained in plain language.

Findings are surfaced through an operations console: a live overview board, per-asset detail with a baseline/drift diff viewer, an incident feed, role-based access (Admin / Viewer), and a tamper-evident audit ledger.

## AI disclosure (BYOK — required by the rules)

- **Provider:** Google Gemini
- **Model:** `gemini-2.5-flash`
- **Key:** `GEMINI_API_KEY` (server-side only; never shipped to the client)
- The AI prioritizes and explains real findings — it does not generate them.

## Run

```bash
npm install
cp .env.example .env.local   # add GEMINI_API_KEY for the AI verdict
npm run dev                  # development — http://localhost:3000
```

For a production build locally: `npm run build && npm run start`.

Open [http://localhost:3000](http://localhost:3000). Live scan at `/scan`; sign-in at `/login`.

## Stack

Next.js 15 (App Router, Vercel) · Tailwind 4 · Node scan engine (pinned http/https) · Zod input validation · Google Gemini (BYOK) · OSV.dev · security headers via `next.config.ts`.
