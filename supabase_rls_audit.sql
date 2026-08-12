-- =====================================================================
-- Nova (esclationsys) — Read-only RLS audit
-- =====================================================================
-- Run this in Supabase Dashboard → SQL Editor. It only SELECTs from
-- Postgres' own catalogs — it does not read or change any of your
-- actual data, and it is 100% safe to run as many times as you want.
--
-- What it shows you, for every table this app actually uses:
--   1) Does the table exist, and is Row Level Security turned ON?
--   2) What policies (if any) exist on it, and what do they allow?
--   3) A plain-language verdict: OPEN (no protection), LOCKED
--      (RLS on, zero policies — blocks everyone including admins,
--      usually a bug), or POLICED (RLS on with policies — read the
--      policy list to judge if they're correct).
--
-- Read the "verdict" column first. Anything other than POLICED on the
-- app's own tables means the client-side admin checks (isAdmin,
-- adminRole, canDelete()) are the only thing standing between a
-- regular signed-in user and full read/write/delete of that table.
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
    when r.table_name is null then '❌ TABLE NOT FOUND — check the name'
    when r.rls_enabled = false then '🔴 OPEN — RLS is OFF, anyone with the anon key has full access'
    when r.rls_enabled = true and coalesce(p.policy_count, 0) = 0
      then '🟠 LOCKED — RLS is ON but has 0 policies (blocks everyone, including admins)'
    else '🟢 POLICED — RLS is on with ' || p.policy_count || ' policy/policies, see detail query below'
  end as verdict
from app_tables t
left join rls_state r on r.table_name = t.table_name
left join policy_counts p on p.table_name = t.table_name
order by t.table_name;


-- ---------------------------------------------------------------------
-- Detail: every policy that exists on the app's tables today — the
-- actual condition each one enforces, so you can read whether it says
-- what you think it says.
-- ---------------------------------------------------------------------
select
  tablename as table_name,
  policyname as policy_name,
  cmd as applies_to,          -- SELECT / INSERT / UPDATE / DELETE / ALL
  roles,                       -- which DB roles it applies to
  qual as using_expression,    -- condition checked for existing rows
  with_check as check_expression -- condition checked for new/changed rows
from pg_policies
where schemaname = 'public'
  and tablename in (
    'profiles', 'categories', 'scripts', 'general_info', 'critical_items',
    'etiquette_items', 'updates', 'suggestions', 'technical_issues',
    'user_presence', 'training_problems', 'training_nodes', 'training_options'
  )
order by tablename, policyname;


-- ---------------------------------------------------------------------
-- Privilege-escalation check: does anything let a regular user UPDATE
-- their own `profiles.role`? If this returns any row, read it
-- carefully — an UPDATE policy on profiles that isn't clearly
-- restricted (or that's missing entirely, meaning updates are
-- currently unrestricted) is how a normal employee could promote
-- themselves to admin.
-- ---------------------------------------------------------------------
select
  policyname as policy_name,
  cmd as applies_to,
  qual as using_expression,
  with_check as check_expression
from pg_policies
where schemaname = 'public'
  and tablename = 'profiles'
  and cmd in ('UPDATE', 'ALL');
