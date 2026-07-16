-- Visual evidence, favicon identity, and ad-hoc baseline persistence.

alter table public.baselines
  add column if not exists favicon_hash text;

alter table public.scans
  add column if not exists diff_path text,
  add column if not exists visual_drift_pct numeric,
  add column if not exists favicon_hash text,
  add column if not exists favicon_changed boolean not null default false;

create table if not exists public.adhoc_baselines (
  target_key      text primary key,
  target_url      text not null,
  html_snapshot   text,
  signals         jsonb not null default '{}'::jsonb,
  screenshot_path text,
  favicon_hash    text,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

create index if not exists adhoc_baselines_updated_idx
  on public.adhoc_baselines (updated_at desc);

alter table public.adhoc_baselines enable row level security;

create or replace function public.fn_touch_adhoc_baselines()
returns trigger language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists touch_adhoc_baselines on public.adhoc_baselines;
create trigger touch_adhoc_baselines
  before update on public.adhoc_baselines
  for each row execute function public.fn_touch_adhoc_baselines();
