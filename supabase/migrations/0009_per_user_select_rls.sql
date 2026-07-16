-- Per-user read isolation for monitoring tables.
-- Admins retain full SELECT. Non-admins only see assets they own (and children).
-- New self-serve signups become analysts so they can create/scan their own assets.

-- ---------------------------------------------------------------------------
-- Signup default role: analyst (self-serve monitoring)
-- ---------------------------------------------------------------------------
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, role)
  values (new.id, new.email, 'analyst')
  on conflict (id) do nothing;
  return new;
end;
$$;

-- ---------------------------------------------------------------------------
-- Ownership helper (SECURITY DEFINER so child-table policies can resolve owner)
-- ---------------------------------------------------------------------------
create or replace function public.user_owns_asset(p_asset_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.assets a
    where a.id = p_asset_id
      and (
        public.current_user_role() = 'admin'
        or a.owner = auth.uid()
      )
  );
$$;

revoke all on function public.user_owns_asset(uuid) from public, anon;
grant execute on function public.user_owns_asset(uuid) to authenticated, service_role;

-- Backfill null owners to the oldest admin (or leave null → admin-only visibility).
update public.assets a
set owner = (
  select p.id from public.profiles p where p.role = 'admin' order by p.created_at asc limit 1
)
where a.owner is null
  and exists (select 1 from public.profiles p where p.role = 'admin');

-- ---------------------------------------------------------------------------
-- SELECT policies
-- ---------------------------------------------------------------------------
drop policy if exists assets_select on public.assets;
create policy assets_select on public.assets
  for select to authenticated
  using (
    public.current_user_role() = 'admin'
    or owner = auth.uid()
  );

-- Analysts (and admins) may insert; owner must be self unless admin.
drop policy if exists assets_write on public.assets;
create policy assets_write on public.assets
  for insert to authenticated
  with check (
    public.current_user_role() = 'admin'
    or (
      public.current_user_role() = 'analyst'
      and owner = auth.uid()
    )
  );

drop policy if exists scans_select on public.scans;
create policy scans_select on public.scans
  for select to authenticated
  using (public.user_owns_asset(asset_id));

drop policy if exists findings_select on public.findings;
create policy findings_select on public.findings
  for select to authenticated
  using (public.user_owns_asset(asset_id));

drop policy if exists incidents_select on public.incidents;
create policy incidents_select on public.incidents
  for select to authenticated
  using (public.user_owns_asset(asset_id));

drop policy if exists alerts_select on public.alerts;
create policy alerts_select on public.alerts
  for select to authenticated
  using (asset_id is null or public.user_owns_asset(asset_id));

drop policy if exists scan_jobs_select on public.scan_jobs;
create policy scan_jobs_select on public.scan_jobs
  for select to authenticated
  using (public.user_owns_asset(asset_id));

drop policy if exists scan_stages_select on public.scan_stages;
create policy scan_stages_select on public.scan_stages
  for select to authenticated
  using (
    exists (
      select 1 from public.scans s
      where s.id = scan_id
        and public.user_owns_asset(s.asset_id)
    )
  );

drop policy if exists baselines_select on public.baselines;
create policy baselines_select on public.baselines
  for select to authenticated
  using (public.user_owns_asset(asset_id));

-- Analysts may only update incidents on assets they own.
drop policy if exists incidents_update on public.incidents;
create policy incidents_update on public.incidents
  for update to authenticated
  using (
    public.current_user_role() = 'admin'
    or (
      public.current_user_role() = 'analyst'
      and public.user_owns_asset(asset_id)
    )
  )
  with check (
    public.current_user_role() = 'admin'
    or (
      public.current_user_role() = 'analyst'
      and public.user_owns_asset(asset_id)
    )
  );
