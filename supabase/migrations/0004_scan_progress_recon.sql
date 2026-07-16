-- Scan proof: persist port/subdomain recon + optional stage progress.

alter table public.scans
  add column if not exists ports_json jsonb not null default '[]'::jsonb,
  add column if not exists subdomains_json jsonb not null default '[]'::jsonb;

create table if not exists public.scan_stages (
  id          uuid primary key default gen_random_uuid(),
  scan_id     uuid not null references public.scans (id) on delete cascade,
  stage       text not null,
  pct         integer not null check (pct between 0 and 100),
  message     text not null,
  artifact    text,
  created_at  timestamptz not null default now()
);

create index if not exists scan_stages_scan_idx
  on public.scan_stages (scan_id, created_at asc);

alter table public.scan_stages enable row level security;

drop policy if exists scan_stages_select on public.scan_stages;
create policy scan_stages_select on public.scan_stages
  for select to authenticated using (true);
