-- Close default-deny gap on adhoc_baselines: per-user RLS for authenticated clients.
-- Service-role server writes remain unchanged (bypass RLS); these policies add
-- defense-in-depth if PostgREST is used directly and document intended access.

drop policy if exists adhoc_baselines_select on public.adhoc_baselines;
create policy adhoc_baselines_select on public.adhoc_baselines
  for select to authenticated
  using (
    public.current_user_role() = 'admin'
    or user_id = auth.uid()
  );

drop policy if exists adhoc_baselines_insert on public.adhoc_baselines;
create policy adhoc_baselines_insert on public.adhoc_baselines
  for insert to authenticated
  with check (
    public.current_user_role() = 'admin'
    or (
      public.current_user_role() = 'analyst'
      and user_id = auth.uid()
    )
  );

drop policy if exists adhoc_baselines_update on public.adhoc_baselines;
create policy adhoc_baselines_update on public.adhoc_baselines
  for update to authenticated
  using (
    public.current_user_role() = 'admin'
    or (
      public.current_user_role() = 'analyst'
      and user_id = auth.uid()
    )
  )
  with check (
    public.current_user_role() = 'admin'
    or (
      public.current_user_role() = 'analyst'
      and user_id = auth.uid()
    )
  );

drop policy if exists adhoc_baselines_delete on public.adhoc_baselines;
create policy adhoc_baselines_delete on public.adhoc_baselines
  for delete to authenticated
  using (
    public.current_user_role() = 'admin'
    or (
      public.current_user_role() = 'analyst'
      and user_id = auth.uid()
    )
  );
