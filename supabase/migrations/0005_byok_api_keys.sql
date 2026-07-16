-- BYOK secrets: never selectable by clients. Server uses service role after
-- auth.uid() checks. Users set keys via SECURITY DEFINER RPCs only.

create table if not exists public.user_api_keys (
  user_id uuid primary key references public.profiles (id) on delete cascade,
  gemini_api_key text,
  shodan_api_key text,
  updated_at timestamptz not null default now()
);

alter table public.user_api_keys enable row level security;
-- Intentionally no policies for authenticated/anon: deny-by-default.

create or replace function public.set_my_api_keys(
  p_gemini text default null,
  p_shodan text default null,
  p_clear_gemini boolean default false,
  p_clear_shodan boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  uid uuid := auth.uid();
  g text;
  s text;
begin
  if uid is null then
    raise exception 'not authenticated';
  end if;

  insert into public.user_api_keys (user_id)
  values (uid)
  on conflict (user_id) do nothing;

  select gemini_api_key, shodan_api_key into g, s
  from public.user_api_keys where user_id = uid;

  if p_clear_gemini then
    g := null;
  elsif p_gemini is not null and length(trim(p_gemini)) > 0 then
    g := trim(p_gemini);
  end if;

  if p_clear_shodan then
    s := null;
  elsif p_shodan is not null and length(trim(p_shodan)) > 0 then
    s := trim(p_shodan);
  end if;

  update public.user_api_keys
  set gemini_api_key = g,
      shodan_api_key = s,
      updated_at = now()
  where user_id = uid;

  return jsonb_build_object(
    'geminiConfigured', g is not null and length(g) > 0,
    'shodanConfigured', s is not null and length(s) > 0
  );
end;
$$;

create or replace function public.get_my_api_key_status()
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  uid uuid := auth.uid();
  g text;
  s text;
begin
  if uid is null then
    raise exception 'not authenticated';
  end if;

  select gemini_api_key, shodan_api_key into g, s
  from public.user_api_keys where user_id = uid;

  return jsonb_build_object(
    'geminiConfigured', g is not null and length(g) > 0,
    'shodanConfigured', s is not null and length(s) > 0
  );
end;
$$;

revoke all on function public.set_my_api_keys(text, text, boolean, boolean) from public;
revoke all on function public.get_my_api_key_status() from public;
grant execute on function public.set_my_api_keys(text, text, boolean, boolean) to authenticated;
grant execute on function public.get_my_api_key_status() to authenticated;
