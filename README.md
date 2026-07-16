# Datum

**Website defacement detection & vulnerability assessment** — System Siege PS-005.

Datum watches public web assets you own: it takes baselines (HTML / visual), runs live assessments (headers, TLS/DNS, ports, content drift, optional enrichment), scores posture, and opens incidents when something looks wrong. The console covers assets, live scan, incidents, audit, members (RBAC), and optional Discord / Gemini BYOK.

**Recommended:** use the hosted app — private server secrets are not in this repo **by design**.

| | |
|---|---|
| Live app | **[https://systemsiege.vercel.app](https://systemsiege.vercel.app)** |
| Repo | [github.com/navneetxdd/c0mr4d35](https://github.com/navneetxdd/c0mr4d35) |

---

## Why local often “doesn’t work”

Clones only get **public** env (`NEXT_PUBLIC_SUPABASE_*`). That is enough for the browser client.

**Private** keys (`SUPABASE_SERVICE_ROLE_KEY`, `BYOK_ENCRYPTION_SECRET`, `CRON_SECRET`) are never committed. Without them, localhost may fail login, rate limits, scans, or BYOK — that is intentional, not a bug. Use Vercel, or get private keys from a teammate out-of-band (**never** commit them).

---

## Option A — Hosted (Vercel) · preferred

1. Open [https://systemsiege.vercel.app](https://systemsiege.vercel.app)
2. Sign in or request access on `/login`
3. Confirm email if prompted
4. Use **Live Scan** (`/scan`) or register assets under **Assets**

Hard-refresh (`Ctrl+Shift+R` / `Cmd+Shift+R`) if the login page looks stuck after a deploy.

No local Node install or `.env` required.

---

## Option B — Run locally

### Dependencies

| Need | Notes |
|------|--------|
| **Node.js 20+** (22 recommended) | Runtime for Next.js |
| **npm** | Comes with Node; run `npm install` |
| **Git** | Clone the repo |
| **Public env** | Bootstrapped by `npm run setup` from `.env.example` |
| **Private env** (optional) | Service role / BYOK / cron — teammate only, or skip and use Vercel |
| **Gemini / Shodan / Discord** | Optional enrichment & alerts |

**npm packages** (installed via `npm install` — see `package.json`):

- **App:** Next.js 15, React 19, Tailwind 4, Zod, Framer Motion, Phosphor icons  
- **Backend / data:** `@supabase/ssr`, `@supabase/supabase-js`  
- **Scan engine:** Playwright Core, `@sparticuz/chromium-min`, pngjs, pixelmatch, murmurhash  

You do **not** install Chromium separately for most local runs; the project pulls a remote Chromium pack when needed (`CHROMIUM_REMOTE_EXEC_PATH` in `.env.example`).

### Steps

```bash
git clone https://github.com/navneetxdd/c0mr4d35.git
cd c0mr4d35
npm install
npm run setup    # creates/merges .env.local with public Supabase values
npm run dev      # http://localhost:3000
```

Open [http://localhost:3000/login](http://localhost:3000/login).

**Production-style local build:**

```bash
npm run build
npm run start
```

### Environment variables

| Variable | Where | Purpose |
|----------|--------|---------|
| `NEXT_PUBLIC_SUPABASE_URL` | Public (in `.env.example`) | Supabase project URL |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Public | Browser / RLS-scoped client |
| `NEXT_PUBLIC_APP_URL` | Public | Local: `http://localhost:3000` · Vercel: production URL |
| `SUPABASE_SERVICE_ROLE_KEY` | **Private** | Scans, rate limits, server persistence |
| `BYOK_ENCRYPTION_SECRET` | **Private** | Encrypt per-user API keys in Settings |
| `CRON_SECRET` | **Private** | Scheduled scan endpoint |
| `GEMINI_API_KEY` | Optional | Deploy-level AI fallback |
| `SHODAN_API_KEY` | Optional | Extra port/CVE enrichment |
| `DISCORD_WEBHOOK_URL` | Optional | Incident alerts |
| `CHROMIUM_*` | Optional | Screenshot / visual baseline path |

If login shows **Local env incomplete** / **Missing local env**:

```bash
# stop the dev server first
npm run setup
npm run dev
```

Still broken → delete `.env.local`, run `npm run setup` again, restart (Next loads env only at startup).

If auth still fails on localhost without private keys → use [https://systemsiege.vercel.app](https://systemsiege.vercel.app). That is the expected path for demos and classmates.

### Database / Auth redirects

Migrations live in `supabase/migrations/` (`0001`–`0008`). The shared Supabase project already has them applied.

For local auth callbacks, Supabase **Authentication → URL Configuration** should allow:

- `http://localhost:3000`
- `http://localhost:3000/auth/callback`

---

## Deploy on Vercel

1. Import the GitHub repo into a Vercel project  
2. Set **all** env vars used in production (public + private), including:
   - `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`
   - `NEXT_PUBLIC_APP_URL` = your Vercel URL (e.g. `https://systemsiege.vercel.app`)
   - `SUPABASE_SERVICE_ROLE_KEY`, `BYOK_ENCRYPTION_SECRET`
   - Optional: `CRON_SECRET`, `GEMINI_API_KEY`, `DISCORD_WEBHOOK_URL`, …  
3. Deploy — framework preset: Next.js  
4. In Supabase Auth URL config, allow the Vercel origin + `/auth/callback`

---

## Console map

| Route | Role |
|-------|------|
| `/scan` | Live assessment of a target URL |
| `/assets` | Register / baseline / rescan owned sites |
| `/incidents` | High-severity findings & triage |
| `/audit` | Append-only activity ledger |
| `/members` | RBAC |
| `/settings` | Profile + BYOK API keys |

---

## AI & posture score

- **Gemini** `gemini-2.5-flash` — prefer Settings BYOK; `GEMINI_API_KEY` is optional fallback  
- No Gemini → engine findings still show, without an AI verdict  
- **Posture** starts at **100**; severity penalties (critical −45, high −20, medium −10, low −4). Higher remaining = lighter findings, not uptime.

---

## Stack

Next.js 15 · React 19 · Supabase (Auth, Postgres, Realtime, Storage) · Tailwind 4 · Playwright/Chromium scan path · Zod · OSV.dev · Gemini (optional)
