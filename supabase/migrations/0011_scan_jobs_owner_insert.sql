-- Tighten scan_jobs INSERT: analysts may only enqueue jobs for assets they own.
-- Admins remain unrestricted. Cross-tenant inserts were already blocked in practice
-- by FK + assets SELECT RLS; this makes the ownership rule explicit at write time.

drop policy if exists scan_jobs_insert on public.scan_jobs;
create policy scan_jobs_insert on public.scan_jobs
  for insert to authenticated
  with check (
    public.current_user_role() = 'admin'
    or (
      public.current_user_role() = 'analyst'
      and public.user_owns_asset(asset_id)
    )
  );
