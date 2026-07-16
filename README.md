# Datum

**Website Defacement Detection & Vulnerability Assessment Platform** — System Siege PS-005.

Establish the truth of a web asset, then watch for the moment it stops being true. Datum baselines public URLs, runs continuous passive security assessment, detects content drift/defacement against stored baselines, and surfaces findings through a Supabase-backed console with RBAC, incidents, Discord alerts, and a tamper-evident audit chain.

## Run

```bash
npm install
cp .env.example .env.local
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). Sign in at `/login`. Live ad-hoc assessment at `/scan`.

Production build:

```bash
npm run build && npm run start
```

Deploy to Vercel with the environment variables below set in the project dashboard. Apply Supabase migrations from `supabase/migrations/`. Schedule monitoring with a cron job that `POST`s `/api/cron/scan` every N minutes using `Authorization: Bearer $CRON_SECRET`.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `NEXT_PUBLIC_SUPABASE_URL` | Supabase project URL |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Supabase anon key (client + RLS) |
| `SUPABASE_SERVICE_ROLE_KEY` | Server-only writes (scans, findings, jobs) |
| `GEMINI_API_KEY` | BYOK AI verdict enrichment |
| `DISCORD_WEBHOOK_URL` | Critical/high finding alerts |
| `CRON_SECRET` | Bearer token for `/api/cron/scan` |

## AI disclosure (BYOK)

- **Provider:** Google Gemini
- **Model:** `gemini-2.5-flash`
- **Key:** set per-user in **Settings → API keys**, or optionally `GEMINI_API_KEY` as deploy fallback (server-side only)
- **Shodan:** optional per-user / `SHODAN_API_KEY` for host + DNS enrichment; InternetDB ports/CVEs work without a key
- When Gemini is missing or the call fails, Datum labels the verdict **AI unavailable** and shows raw engine findings as authoritative.

## Posture score (SCORE / 100)

Starts at **100** (clean). Each finding subtracts a severity weight (critical −45, high −20, medium −10, low −4). The number on screen is remaining headroom after penalties — higher is safer. It is **not** uptime, CVE count, or a letter grade.
## Stack

Next.js 15 · Supabase (Auth, Postgres, Realtime) · Tailwind 4 · SSRF-guarded Node scan engine · Zod · OSV.dev CVE correlation · Google Gemini BYOK
