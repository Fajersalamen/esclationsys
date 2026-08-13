-- =====================================================================
-- Nova (esclationsys) — Full check of every table the app uses
-- =====================================================================
-- Run this in Supabase Dashboard → SQL Editor. 100% read-only — it
-- does not change or delete anything. Run it as ONE block (select
-- everything and hit "Run") — it will show 3 separate result tables,
-- one below the other.
--
-- Screenshot me all 3 results and I can tell you exactly which
-- table(s) are broken and how to fix each one.
-- =====================================================================


-- =====================================================================
-- RESULT 1 — RLS status + policy count for every table, with a
-- plain-language verdict.
-- =====================================================================
with app_tables as (
  select unnest(array[
    'profiles', 'categories', 'scripts', 'general_info', 'critical_items',
    'etiquette_items', 'updates', 'suggestions', 'technical_issues',
    'user_presence', 'training_problems', 'training_nodes', 'training_options'
  ]) as table_name
),
rls_state as (
  select c.relname as table_name, c.relrowsecurity as rls_enabled
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and c.relkind = 'r'
),
policy_counts as (
  select tablename as table_name, count(*) as policy_count
  from pg_policies
  where schemaname = 'public'
  group by tablename
)
select
  t.table_name,
  case when r.table_name is null then false else true end as table_exists,
  coalesce(r.rls_enabled, false) as rls_enabled,
  coalesce(p.policy_count, 0) as policy_count,
  case
    when r.table_name is null then '❌ TABLE NOT FOUND'
    when r.rls_enabled = false then '🔴 OPEN — RLS is OFF, no protection at all'
    when r.rls_enabled = true and coalesce(p.policy_count, 0) = 0
      then '🟠 LOCKED — RLS on, 0 policies, blocks EVERYONE incl. admins'
    else '🟢 POLICED — RLS on with ' || p.policy_count || ' polic(ies)'
  end as verdict
from app_tables t
left join rls_state r on r.table_name = t.table_name
left join policy_counts p on p.table_name = t.table_name
order by t.table_name;


-- =====================================================================
-- RESULT 2 — real row counts (this connection bypasses RLS, so these
-- numbers are always the true contents of each table).
-- =====================================================================
select 'categories' as table_name, count(*) as real_row_count from public.categories
union all select 'scripts', count(*) from public.scripts
union all select 'general_info', count(*) from public.general_info
union all select 'critical_items', count(*) from public.critical_items
union all select 'etiquette_items', count(*) from public.etiquette_items
union all select 'updates', count(*) from public.updates
union all select 'suggestions', count(*) from public.suggestions
union all select 'technical_issues', count(*) from public.technical_issues
union all select 'user_presence', count(*) from public.user_presence
union all select 'training_problems', count(*) from public.training_problems
union all select 'training_nodes', count(*) from public.training_nodes
union all select 'training_options', count(*) from public.training_options
order by table_name;


-- =====================================================================
-- RESULT 3 — what a regular signed-in EMPLOYEE (not admin) actually
-- sees for each table right now, simulating a real logged-in session.
--
-- Compare this to RESULT 2:
--   • categories / scripts / general_info / critical_items /
--     etiquette_items / updates / technical_issues / training_problems
--     / training_nodes / training_options
--       → these SHOULD roughly match Result 2 (published rows visible
--         to everyone). If one of these shows 0 while Result 2 shows
--         more than 0, that table's SELECT policy is broken — same
--         bug as technical_issues had.
--   • suggestions
--       → 0 is CORRECT here on purpose (only admins are meant to read
--         suggestions). Don't "fix" this one.
--   • user_presence
--       → 0 is expected unless this simulated user's fake ID happens
--         to match a real row (it won't) — not a meaningful test for
--         this table, ignore it here.
--   • profiles
--       → 0 is expected too (the fake user ID below doesn't exist in
--         profiles) — also not a meaningful test here, ignore it.
-- =====================================================================
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"someone@yourcompany.com","sub":"00000000-0000-0000-0000-000000000000"}';

  select 'categories' as table_name, count(*) as visible_to_employee from public.categories
  union all select 'scripts', count(*) from public.scripts
  union all select 'general_info', count(*) from public.general_info
  union all select 'critical_items', count(*) from public.critical_items
  union all select 'etiquette_items', count(*) from public.etiquette_items
  union all select 'updates', count(*) from public.updates
  union all select 'suggestions', count(*) from public.suggestions
  union all select 'technical_issues', count(*) from public.technical_issues
  union all select 'training_problems', count(*) from public.training_problems
  union all select 'training_nodes', count(*) from public.training_nodes
  union all select 'training_options', count(*) from public.training_options
  order by table_name;
rollback;
-- (rollback only exits the simulated session — we only ran SELECTs, so
-- nothing is undone)
