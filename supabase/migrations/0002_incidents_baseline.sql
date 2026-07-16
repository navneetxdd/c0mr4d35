-- Incidents, baseline HTML snapshots, and scan scheduling helpers.

alter table public.baselines
  add column if not exists html_snapshot text;

alter table public.assets
  add column if not exists last_scanned_at timestamptz;

create table if not exists public.incidents (
  id          uuid primary key default gen_random_uuid(),
  asset_id    uuid not null references public.assets (id) on delete cascade,
  scan_id     uuid references public.scans (id) on delete set null,
  severity    text not null check (severity in ('CRITICAL','HIGH','MEDIUM','LOW')),
  type        text not null,
  status      text not null default 'open' check (status in ('open','acknowledged','resolved')),
  assignee    uuid references auth.users (id) on delete set null,
  detected_at timestamptz not null default now(),
  mttd_sec    integer
);
create index if not exists incidents_asset_idx on public.incidents (asset_id, detected_at desc);
create index if not exists incidents_status_idx on public.incidents (status);

alter table public.incidents enable row level security;

drop policy if exists incidents_select on public.incidents;
create policy incidents_select on public.incidents
  for select to authenticated using (true);

drop policy if exists incidents_update on public.incidents;
create policy incidents_update on public.incidents
  for update to authenticated
  using (public.current_user_role() in ('admin','analyst'))
  with check (public.current_user_role() in ('admin','analyst'));

do $$ begin
  alter publication supabase_realtime add table public.incidents;
exception when duplicate_object then null; when undefined_object then null; end $$;
