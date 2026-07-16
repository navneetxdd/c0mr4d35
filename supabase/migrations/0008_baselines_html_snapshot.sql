-- Ensure HTML baselines work (prod was missing this column vs repo 0002/0003).
alter table public.baselines
  add column if not exists html_snapshot text;
