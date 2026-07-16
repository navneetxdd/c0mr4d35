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
- Optional: Google AI Studio key (Gemini), Shodan key, Discord webhook

### 1. Install + env bootstrap

```bash
git clone https://github.com/navneetxdd/c0mr4d35.git
cd c0mr4d35
npm install
npm run setup
```

`npm run setup` copies `.env.example` → `.env.local` if you do not already have one.
The example includes the **public** Supabase URL + anon key (safe to commit — they already ship in the browser on production).

That is enough to open `/login` and sign in/sign up.

### 2. Private keys (scans / full console)

Add these to `.env.local` (ask a teammate privately — **never commit**):

| Variable | Purpose |
|----------|---------|
| `SUPABASE_SERVICE_ROLE_KEY` | Server-side persistence, rate limits, asset scans |
| `BYOK_ENCRYPTION_SECRET` | Seal per-user API keys (required for Settings BYOK) |
| `CRON_SECRET` | Optional scheduled scans |

Or skip local secrets and use the hosted app: **[https://systemsiege.vercel.app](https://systemsiege.vercel.app)**

If login shows “Local env incomplete”:

```bash
# stop npm run dev first
npm run setup
npm run dev
```

If it still fails: delete `.env.local`, run `npm run setup` again, then restart the dev server (Next only loads env at startup).

### 3. Database

Migrations live in `supabase/migrations/` (`0001` … `0008`). The shared project already has them applied.

In **Supabase → Authentication → URL Configuration** for local work, allow:

- Site URL / redirect: `http://localhost:3000` and `{origin}/auth/callback`

### 4. Dev server

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) → `/login`.

If you see “Missing local env”, you skipped `npm run setup` / `.env.local`.

### 5. Production build (local)

```bash
npm run build
npm run start
```

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
