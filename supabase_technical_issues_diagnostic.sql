-- =====================================================================
-- Nova (esclationsys) — Why did "Technical Issues" numbers disappear?
-- =====================================================================
-- Run this in Supabase Dashboard → SQL Editor, ONE SECTION AT A TIME
-- (select each section below and hit "Run" separately, so the results
-- don't get mixed up). It's 100% read-only — nothing here changes or
-- deletes any data.
--
-- Screenshot me the result of EACH section and I can tell you exactly
-- which policy is wrong and give you the one-line fix.
-- =====================================================================


-- =====================================================================
-- SECTION 1 — Does the data actually still exist?
-- The SQL Editor connects as a superuser that IGNORES RLS completely,
-- so this always shows the real, true contents of the table —
-- regardless of what any policy says. If this shows rows, your data
-- is safe and this is purely an access-control (RLS) problem, not
-- data loss.
-- =====================================================================
select count(*) as real_row_count from public.technical_issues;

select id, phone_number, issue_type, employee_email, created_at
from public.technical_issues
order by id desc
limit 10;


-- =====================================================================
-- SECTION 2 — What RLS policies currently exist on this table, and
-- what do they actually check?
-- =====================================================================
select relrowsecurity as rls_is_enabled
from pg_class
where relname = 'technical_issues';

select
  policyname as policy_name,
  cmd as applies_to,          -- SELECT / INSERT / UPDATE / DELETE
  roles,
  qual as using_expression,       -- condition for reading/matching existing rows
  with_check as check_expression  -- condition for new/changed rows
from pg_policies
where schemaname = 'public' and tablename = 'technical_issues';


-- =====================================================================
-- SECTION 3 — The real test: pretend to BE a logged-in employee (the
-- same way the app connects) and run the exact query the app runs,
-- to see whether RLS is what's hiding the rows.
--
-- Replace 'someone@yourcompany.com' below with any real employee
-- email that has technical issues logged under it (check Section 1's
-- results for a real employee_email value to use).
-- =====================================================================
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"someone@yourcompany.com","sub":"00000000-0000-0000-0000-000000000000"}';

  -- this is the exact query app.js runs after login:
  select count(*) as rows_visible_to_a_logged_in_employee
  from public.technical_issues;
rollback;
-- (rollback just exits the simulated session cleanly — it does not undo
-- anything, since we only ran SELECTs above)


-- =====================================================================
-- HOW TO READ THE RESULTS
-- • Section 1 shows real rows  →  your data is fine, nothing was lost.
-- • Section 2 shows rls_is_enabled = true but ZERO policy rows
--     →  RLS is on with no rules at all, which blocks EVERYONE
--        (including admins). This is the most likely cause if the
--        earlier script hit an error partway through and rolled back.
-- • Section 3 returns 0  →  confirmed: RLS is why the app shows an
--     empty list. Send me the Section 2 output and I'll give you the
--     exact CREATE POLICY line to fix it.
-- • Section 3 returns the same count as Section 1  →  RLS is fine;
--     the problem is somewhere else (e.g. a stale deploy) and I'll
--     need to look at the app side instead.
-- =====================================================================
