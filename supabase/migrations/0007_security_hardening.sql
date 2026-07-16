-- 0007_security_hardening.sql
-- Closes SL-1 anon rate-limit DoS, audit html_snapshot leak, truncate gap,
-- and hardens SECURITY DEFINER execute grants.

-- ---------------------------------------------------------------------------
-- SL-1: rate_limit_check must not be callable with the anon key.
-- App uses createAdminClient() (service_role) — REVOKE does not break login.
-- ---------------------------------------------------------------------------
revoke all on function public.rate_limit_check(text, integer, integer) from public;
revoke all on function public.rate_limit_check(text, integer, integer) from anon;
revoke all on function public.rate_limit_check(text, integer, integer) from authenticated;
grant execute on function public.rate_limit_check(text, integer, integer) to service_role;

-- ---------------------------------------------------------------------------
-- Defensive REVOKE on other SECURITY DEFINER helpers
-- ---------------------------------------------------------------------------
revoke all on function public.current_user_role() from public;
revoke all on function public.current_user_role() from anon;
grant execute on function public.current_user_role() to authenticated;
grant execute on function public.current_user_role() to service_role;

revoke all on function public.fn_audit() from public, anon, authenticated;
revoke all on function public.fn_block_mod() from public, anon, authenticated;
grant execute on function public.fn_audit() to postgres, service_role;
grant execute on function public.fn_block_mod() to postgres, service_role;

revoke all on function public.set_my_api_keys(text, text, boolean, boolean) from public, anon;
grant execute on function public.set_my_api_keys(text, text, boolean, boolean) to authenticated, service_role;

revoke all on function public.get_my_api_key_status() from public, anon;
grant execute on function public.get_my_api_key_status() to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- SL-2: strip html_snapshot (and html) from audit detail
-- ---------------------------------------------------------------------------
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
  perform pg_advisory_xact_lock(918273645);
  select this_hash into v_prev from public.audit_log order by seq desc limit 1;

  if tg_op = 'DELETE' then
    v_target := old.id::text;
    v_detail := to_jsonb(old);
  else
    v_target := new.id::text;
    v_detail := to_jsonb(new);
  end if;

  -- Never persist raw page bodies in the immutable ledger
  v_detail := v_detail - 'html' - 'html_snapshot';

  v_hash := encode(
    extensions.digest(
      coalesce(v_prev, 'genesis') || v_action || coalesce(v_target, '') || v_detail::text || v_ts::text,
      'sha256'
    ),
    'hex'
  );

  insert into public.audit_log (actor, action, target_table, target_id, detail, prev_hash, this_hash, created_at)
  values (v_actor, v_action, tg_table_name, v_target, v_detail, v_prev, v_hash, v_ts);

  return coalesce(new, old);
end;
$$;

revoke all on function public.fn_audit() from public, anon, authenticated;
grant execute on function public.fn_audit() to postgres, service_role;

-- ---------------------------------------------------------------------------
-- SL-3: block TRUNCATE on audit_log (UPDATE/DELETE already blocked)
-- ---------------------------------------------------------------------------
drop trigger if exists audit_no_truncate on public.audit_log;
create trigger audit_no_truncate
  before truncate on public.audit_log
  for each statement
  execute function public.fn_block_mod();
