-- Harden shared-tenant RLS + scope ad-hoc baselines per user.

-- Assets: anyone authenticated can read (team console); only owner or admin may update.
drop policy if exists assets_update on public.assets;
create policy assets_update on public.assets
  for update to authenticated
  using (
    public.current_user_role() = 'admin'
    or (
      public.current_user_role() = 'analyst'
      and owner = auth.uid()
    )
  )
  with check (
    public.current_user_role() = 'admin'
    or (
      public.current_user_role() = 'analyst'
      and owner = auth.uid()
    )
  );

-- Baselines: viewers cannot pull html_snapshot via REST; analysts/admins can read.
-- Writes only for assets the caller owns (or admin).
drop policy if exists baselines_select on public.baselines;
create policy baselines_select on public.baselines
  for select to authenticated
  using (public.current_user_role() in ('admin', 'analyst'));

drop policy if exists baselines_write on public.baselines;
create policy baselines_write on public.baselines
  for insert to authenticated
  with check (
    public.current_user_role() = 'admin'
    or (
      public.current_user_role() = 'analyst'
      and exists (
        select 1 from public.assets a
        where a.id = asset_id and a.owner = auth.uid()
      )
    )
  );

-- Ad-hoc baselines: per-user scope (service role writes; no client policies).
alter table public.adhoc_baselines
  add column if not exists user_id uuid references public.profiles (id) on delete cascade;

-- Clear shared/legacy rows so the new composite key is clean.
truncate table public.adhoc_baselines;

alter table public.adhoc_baselines
  alter column user_id set not null;

alter table public.adhoc_baselines drop constraint if exists adhoc_baselines_pkey;

alter table public.adhoc_baselines
  add primary key (user_id, target_key);

create index if not exists adhoc_baselines_user_updated_idx
  on public.adhoc_baselines (user_id, updated_at desc);
