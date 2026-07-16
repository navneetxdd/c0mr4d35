-- ============================================================================
-- Datum — Supabase schema, RBAC, RLS, and tamper-evident audit chain.
-- Run this in the Supabase SQL editor (or `supabase db push`).
--
-- Security model:
--   * Every table has Row Level Security enabled with default-deny.
--   * Roles (admin > analyst > viewer) are resolved by a SECURITY DEFINER
--     helper so policies never recurse through RLS.
--   * The audit log is append-only (a BEFORE UPDATE/DELETE trigger blocks
--     modification for EVERYONE, including service_role) and hash-chained, so
--     tampering is detectable by re-walking the chain.
--   * Writes to scans/findings/alerts happen only via the server using the
--     service role; clients get read-only RLS on them.
-- ============================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------------------
-- Roles & profiles
-- ---------------------------------------------------------------------------
do $$ begin
  create type public.app_role as enum ('admin', 'analyst', 'viewer');
exception when duplicate_object then null; end $$;

create table if not exists public.profiles (
  id         uuid primary key references auth.users (id) on delete cascade,
  email      text,
  role       public.app_role not null default 'viewer',
  created_at timestamptz not null default now()
);

-- Resolve the caller's role WITHOUT triggering RLS recursion.
create or replace function public.current_user_role()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select coalesce((select role::text from public.profiles where id = auth.uid()), 'anon');
$$;

-- New auth users get a viewer profile automatically.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, role)
  values (new.id, new.email, 'viewer')
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------------------------------------------------------------------------
-- Assets
-- ---------------------------------------------------------------------------
create table if not exists public.assets (
  id                 uuid primary key default gen_random_uuid(),
  name               text not null,
  url                text not null,
  owner              uuid references auth.users (id) on delete set null,
  monitoring_enabled boolean not null default false,   -- off by default (on-demand)
  scan_interval_min  integer not null default 60 check (scan_interval_min between 5 and 1440),
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Baselines (established known-good state per asset)
-- ---------------------------------------------------------------------------
create table if not exists public.baselines (
  id              uuid primary key default gen_random_uuid(),
  asset_id        uuid not null references public.assets (id) on delete cascade,
  dom_hash        text,
  signals         jsonb not null default '{}'::jsonb,
  screenshot_path text,
  established_by  uuid references auth.users (id) on delete set null,
  established_at  timestamptz not null default now()
);
create index if not exists baselines_asset_idx on public.baselines (asset_id, established_at desc);

-- ---------------------------------------------------------------------------
-- Scans & findings
-- ---------------------------------------------------------------------------
create table if not exists public.scans (
  id              uuid primary key default gen_random_uuid(),
  asset_id        uuid not null references public.assets (id) on delete cascade,
  status          text not null default 'done' check (status in ('queued','scanning','done','error')),
  trigger         text not null default 'manual' check (trigger in ('manual','cron')),
  http_status     integer,
  posture         text check (posture in ('secure','watch','critical')),
  posture_score   integer,
  drift_pct       numeric,
  pages_scanned   integer,
  tech_stack      jsonb not null default '[]'::jsonb,
  severity_counts jsonb not null default '{}'::jsonb,
  signals         jsonb not null default '{}'::jsonb,
  ai_verdict      jsonb,
  dom_hash        text,
  screenshot_path text,
  error           text,
  created_by      uuid references auth.users (id) on delete set null,
  started_at      timestamptz not null default now(),
  finished_at     timestamptz
);
create index if not exists scans_asset_idx on public.scans (asset_id, started_at desc);

create table if not exists public.findings (
  id          uuid primary key default gen_random_uuid(),
  scan_id     uuid not null references public.scans (id) on delete cascade,
  asset_id    uuid not null references public.assets (id) on delete cascade,
  category    text not null,
  risk        text not null check (risk in ('critical','high','medium','low','info')),
  title       text not null,
  detail      text,
  remediation text,
  evidence    text,
  reference   text,
  owasp       text,
  cwe         text,
  url         text,
  created_at  timestamptz not null default now()
);
create index if not exists findings_scan_idx on public.findings (scan_id);

-- ---------------------------------------------------------------------------
-- Alerts
-- ---------------------------------------------------------------------------
create table if not exists public.alerts (
  id         uuid primary key default gen_random_uuid(),
  asset_id   uuid references public.assets (id) on delete cascade,
  scan_id    uuid references public.scans (id) on delete set null,
  severity   text not null check (severity in ('critical','high','medium','low','info')),
  message    text not null,
  channel    text not null default 'in-app',
  delivered  boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists alerts_created_idx on public.alerts (created_at desc);

-- ---------------------------------------------------------------------------
-- Scan job queue (cron + on-demand, single source of truth)
-- ---------------------------------------------------------------------------
create table if not exists public.scan_jobs (
  id           uuid primary key default gen_random_uuid(),
  asset_id     uuid not null references public.assets (id) on delete cascade,
  status       text not null default 'pending' check (status in ('pending','leased','done','error')),
  trigger      text not null default 'manual' check (trigger in ('manual','cron')),
  lease_until  timestamptz,
  requested_by uuid references auth.users (id) on delete set null,
  created_at   timestamptz not null default now()
);
create index if not exists scan_jobs_status_idx on public.scan_jobs (status, created_at);

-- ---------------------------------------------------------------------------
-- Rate limits (server-side only; no client access)
-- ---------------------------------------------------------------------------
create table if not exists public.rate_limits (
  key          text primary key,
  window_start timestamptz not null default now(),
  count        integer not null default 0
);

-- Atomic fixed-window limiter. Returns true if the action is allowed.
create or replace function public.rate_limit_check(p_key text, p_limit int, p_window_seconds int)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  v_now   timestamptz := now();
  v_count int;
begin
  insert into public.rate_limits (key, window_start, count)
  values (p_key, v_now, 1)
  on conflict (key) do update
    set count = case
                  when public.rate_limits.window_start < v_now - make_interval(secs => p_window_seconds)
                  then 1
                  else public.rate_limits.count + 1
                end,
        window_start = case
                  when public.rate_limits.window_start < v_now - make_interval(secs => p_window_seconds)
                  then v_now
                  else public.rate_limits.window_start
                end
  returning count into v_count;
  return v_count <= p_limit;
end;
$$;

-- ---------------------------------------------------------------------------
-- Audit log — append-only, hash-chained, tamper-evident
-- ---------------------------------------------------------------------------
create table if not exists public.audit_log (
  seq          bigserial primary key,
  actor        uuid,
  action       text not null,
  target_table text,
  target_id    text,
  detail       jsonb,
  prev_hash    text,
  this_hash    text not null,
  created_at   timestamptz not null default now()
);

create or replace function public.fn_audit()
returns trigger
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_prev   text;
  v_actor  uuid := auth.uid();
  v_target text;
  v_detail jsonb;
  v_action text := tg_op || ' ' || tg_table_name;
  v_ts     timestamptz := now();
  v_hash   text;
begin
  -- Serialize chain writes so prev_hash is always the true tip.
  perform pg_advisory_xact_lock(918273645);
  select this_hash into v_prev from public.audit_log order by seq desc limit 1;

  if tg_op = 'DELETE' then
    v_target := old.id::text;
    v_detail := to_jsonb(old);
  else
    v_target := new.id::text;
    v_detail := to_jsonb(new);
  end if;
  v_detail := v_detail - 'html';  -- never store raw page bodies in the audit trail

  v_hash := encode(
    extensions.digest(coalesce(v_prev, 'genesis') || v_action || coalesce(v_target,'') || v_detail::text || v_ts::text, 'sha256'),
    'hex'
  );

  insert into public.audit_log (actor, action, target_table, target_id, detail, prev_hash, this_hash, created_at)
  values (v_actor, v_action, tg_table_name, v_target, v_detail, v_prev, v_hash, v_ts);

  return coalesce(new, old);
end;
$$;

-- Make audit_log append-only for EVERYONE (including service_role): a trigger
-- fires regardless of RLS-bypass privileges.
create or replace function public.fn_block_mod()
returns trigger
language plpgsql
as $$
begin
  raise exception 'audit_log is append-only and cannot be modified';
end;
$$;

drop trigger if exists audit_no_mod on public.audit_log;
create trigger audit_no_mod
  before update or delete on public.audit_log
  for each row execute function public.fn_block_mod();

-- Attach audit to the mutating tables that matter.
drop trigger if exists audit_assets on public.assets;
create trigger audit_assets
  after insert or update or delete on public.assets
  for each row execute function public.fn_audit();

drop trigger if exists audit_profiles on public.profiles;
create trigger audit_profiles
  after update on public.profiles
  for each row execute function public.fn_audit();

drop trigger if exists audit_baselines on public.baselines;
create trigger audit_baselines
  after insert or update or delete on public.baselines
  for each row execute function public.fn_audit();

-- ---------------------------------------------------------------------------
-- updated_at maintenance
-- ---------------------------------------------------------------------------
create or replace function public.fn_touch_updated()
returns trigger language plpgsql as $$
begin new.updated_at := now(); return new; end;
$$;
drop trigger if exists touch_assets on public.assets;
create trigger touch_assets before update on public.assets
  for each row execute function public.fn_touch_updated();

-- ============================================================================
-- Row Level Security
-- ============================================================================
alter table public.profiles   enable row level security;
alter table public.assets     enable row level security;
alter table public.baselines  enable row level security;
alter table public.scans      enable row level security;
alter table public.findings   enable row level security;
alter table public.alerts     enable row level security;
alter table public.scan_jobs  enable row level security;
alter table public.audit_log  enable row level security;
alter table public.rate_limits enable row level security;

-- profiles: read self (or admin reads all); only admin changes roles.
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles
  for select to authenticated
  using (id = auth.uid() or public.current_user_role() = 'admin');

drop policy if exists profiles_update_admin on public.profiles;
create policy profiles_update_admin on public.profiles
  for update to authenticated
  using (public.current_user_role() = 'admin')
  with check (public.current_user_role() = 'admin');

-- assets: everyone authenticated reads; analyst/admin write; admin deletes.
drop policy if exists assets_select on public.assets;
create policy assets_select on public.assets
  for select to authenticated using (true);

drop policy if exists assets_write on public.assets;
create policy assets_write on public.assets
  for insert to authenticated
  with check (public.current_user_role() in ('admin','analyst'));

drop policy if exists assets_update on public.assets;
create policy assets_update on public.assets
  for update to authenticated
  using (public.current_user_role() in ('admin','analyst'))
  with check (public.current_user_role() in ('admin','analyst'));

drop policy if exists assets_delete on public.assets;
create policy assets_delete on public.assets
  for delete to authenticated
  using (public.current_user_role() = 'admin');

-- baselines: read all; analyst/admin establish.
drop policy if exists baselines_select on public.baselines;
create policy baselines_select on public.baselines
  for select to authenticated using (true);
drop policy if exists baselines_write on public.baselines;
create policy baselines_write on public.baselines
  for insert to authenticated
  with check (public.current_user_role() in ('admin','analyst'));

-- scans / findings / alerts: read-only for clients; writes go through service role.
drop policy if exists scans_select on public.scans;
create policy scans_select on public.scans
  for select to authenticated using (true);

drop policy if exists findings_select on public.findings;
create policy findings_select on public.findings
  for select to authenticated using (true);

drop policy if exists alerts_select on public.alerts;
create policy alerts_select on public.alerts
  for select to authenticated using (true);

-- scan_jobs: read all; analyst/admin may enqueue.
drop policy if exists scan_jobs_select on public.scan_jobs;
create policy scan_jobs_select on public.scan_jobs
  for select to authenticated using (true);
drop policy if exists scan_jobs_insert on public.scan_jobs;
create policy scan_jobs_insert on public.scan_jobs
  for insert to authenticated
  with check (public.current_user_role() in ('admin','analyst'));

-- audit_log: admins read; NO client writes (only the SECURITY DEFINER trigger).
drop policy if exists audit_select_admin on public.audit_log;
create policy audit_select_admin on public.audit_log
  for select to authenticated
  using (public.current_user_role() = 'admin');

-- rate_limits: no client policies at all (service role only, bypasses RLS).

-- ============================================================================
-- Realtime: expose the tables the live console subscribes to.
-- ============================================================================
do $$ begin
  alter publication supabase_realtime add table public.scans;
exception when duplicate_object then null; when undefined_object then null; end $$;
do $$ begin
  alter publication supabase_realtime add table public.findings;
exception when duplicate_object then null; when undefined_object then null; end $$;
do $$ begin
  alter publication supabase_realtime add table public.alerts;
exception when duplicate_object then null; when undefined_object then null; end $$;
