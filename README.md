# Datum

**Website Defacement Detection & Vulnerability Assessment Platform** — System Siege PS-005.

Datum baselines public web assets, continuously assesses them for content drift and common security weaknesses, and surfaces results in an authenticated operations console (assets, live scan, incidents, audit ledger, RBAC members, and Discord alerts).

Live deployment: **[https://systemsiege.vercel.app](https://systemsiege.vercel.app)**

---

## What it does

- **Baselines** HTML/visual snapshots of owned assets so later scans can detect unexpected change
- **Live assessment** against a target URL (headers, TLS/DNS hygiene, ports, subdomains, content/behavior signals, optional enrichment)
- **Posture scoring** from findings (starts at 100; severity penalties reduce the score)
- **Incidents & alerts** when high-severity findings land
- **Team access** via Supabase Auth + role-based console access
- **Optional AI verdicts** via per-user Gemini keys in Settings (or a deploy-level fallback)

---

## Use the hosted app

1. Open [https://systemsiege.vercel.app](https://systemsiege.vercel.app)
2. You’ll land on `/login` — sign in or request access (signup)
3. Confirm your email if prompted, then return to the console
4. Start with **Live Scan** (`/scan`) or register assets under **Assets**

If the login page looks blank or stuck after a deploy, hard-refresh once (`Ctrl+Shift+R` / `Cmd+Shift+R`).

---

## Run locally

### Prerequisites

- Node.js 20+ (22 recommended)
- A Supabase project (Auth + Postgres)
- Optional: Google AI Studio key (Gemini), Shodan key, Discord webhook

### 1. Install

```bash
git clone https://github.com/navneetxdd/c0mr4d35.git
cd c0mr4d35
npm install
```

### 2. Configure environment

```bash
cp .env.example .env.local
```

Fill at least:

| Variable | Required | Purpose |
|----------|----------|---------|
| `NEXT_PUBLIC_SUPABASE_URL` | Yes | Supabase project URL |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Yes | Supabase anon key |
| `SUPABASE_SERVICE_ROLE_KEY` | Yes | Server-side persistence |
| `NEXT_PUBLIC_APP_URL` | Yes (prod) | Public app origin for auth redirects (e.g. `https://systemsiege.vercel.app` or `http://localhost:3000`) |
| `CRON_SECRET` | Recommended | Bearer secret for scheduled scans |
| `BYOK_ENCRYPTION_SECRET` | Recommended | Seals per-user API keys at rest |
| `GEMINI_API_KEY` | Optional | Deploy-level Gemini fallback |
| `SHODAN_API_KEY` | Optional | Deploy-level Shodan fallback |
| `DISCORD_WEBHOOK_URL` | Optional | High-severity alerts |
| `CHROMIUM_EXECUTABLE_PATH` | Optional (local) | Local Chrome/Edge path for screenshots |
| `CHROMIUM_REMOTE_EXEC_PATH` | Optional (Vercel) | Remote Chromium pack URL for serverless screenshots |

### 3. Database

Apply SQL migrations in `supabase/migrations/` to your Supabase project (SQL editor or Supabase CLI), in order (`0001` … `0006`).

In **Supabase → Authentication → URL Configuration**:

- **Site URL:** your app origin (`http://localhost:3000` for local, `https://systemsiege.vercel.app` for production)
- **Redirect URLs:** include `{origin}/auth/callback`

### 4. Dev server

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) → `/login`.

### 5. Production build (local)

```bash
npm run build
npm run start
```

---

## Deploy on Vercel

1. Import the GitHub repo into Vercel (or use the existing project)
2. Set the same environment variables from `.env.example` in the Vercel project settings (Production + Preview as needed)
3. Set `NEXT_PUBLIC_APP_URL=https://systemsiege.vercel.app`
4. Deploy — production URL: [https://systemsiege.vercel.app](https://systemsiege.vercel.app)
5. Keep Supabase Auth Site URL / Redirect URLs aligned with that origin

### Scheduled scans

`POST` to `/api/cron/scan` on a schedule with:

```http
Authorization: Bearer <CRON_SECRET>
```

Configure this with Vercel Cron or any external scheduler.

---

## Console map

| Route | Purpose |
|-------|---------|
| `/` | Command overview |
| `/assets` | Asset register + monitoring |
| `/scan` | Ad-hoc live assessment |
| `/incidents` | Incident feed |
| `/audit` | Append-only audit ledger |
| `/members` | Org roster / roles |
| `/settings` | Workspace + per-user API keys |

---

## AI (BYOK)

- **Provider:** Google Gemini · **Model:** `gemini-2.5-flash`
- Prefer **Settings → API keys** per user; `GEMINI_API_KEY` is an optional deploy fallback
- Shodan is optional; InternetDB port/CVE enrichment works without a Shodan key
- If Gemini is unavailable, the console shows engine findings without an AI verdict

## Posture score

Starts at **100**. Findings subtract by severity (critical −45, high −20, medium −10, low −4). Higher remaining score means fewer/lighter findings — not uptime and not a letter grade.

---

## Stack

Next.js 15 · Supabase (Auth, Postgres, Realtime, Storage) · Tailwind 4 · Node scan engine · Zod · OSV.dev · Google Gemini (optional)
