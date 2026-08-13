-- =====================================================================
-- Nova (esclationsys) — Deep RLS security test (v2)
-- =====================================================================
-- v1 tried to create fake temporary profile rows and Postgres rejected
-- it: profiles.id is a foreign key to auth.users, so you can't insert
-- a profiles row for a user that doesn't really exist. This version
-- uses two REAL existing user IDs from your own profiles table
-- instead — and still never permanently changes anything, because
-- every check runs inside BEGIN/ROLLBACK. Safe to run on production.
--
-- STEP 1: run the lookup below by itself first, and copy two real ids:
--   • one row where role is NOT 'admin' (any agent/quality/team_leader)
--   • one row where role = 'admin'
-- =====================================================================
select id, role from public.profiles order by role;


-- =====================================================================
-- STEP 2: paste your two copied ids into the two placeholders below —
-- search this file for AGENT_ID_HERE and ADMIN_ID_HERE and replace
-- both occurrences of each with the real id you copied (keep the
-- quotes). Then run everything from here down.
--
-- Run it in TWO passes:
--   PASS A: CHECK 0 + CHECK 1 + CHECK 4 + CHECK 5 together. None of
--           these should show a red error — just rows to read.
--   PASS B: run CHECK 2 alone, then CHECK 3 alone, separately from
--           everything else. For THESE TWO, a RED ERROR saying "new
--           row violates row-level security policy" is the correct,
--           good result. Running them together with the others would
--           let one real error stop the rest of the script (the same
--           thing that caused the last incident).
-- =====================================================================


-- ---------------------------------------------------------------------
-- CHECK 0 — policy hygiene: does any table have more than one policy
-- for the same command? Expect ZERO rows back.
-- ---------------------------------------------------------------------
select tablename, cmd, count(*) as policy_count,
       array_agg(policyname) as policy_names
from pg_policies
where schemaname = 'public'
group by tablename, cmd
having count(*) > 1
order by tablename, cmd;


-- ---------------------------------------------------------------------
-- CHECK 1 — using a REAL non-admin employee's own id, can they promote
-- themselves to admin? Expect: 0 rows returned. A row showing
-- role = 'admin' is a CRITICAL bug. (Rolled back either way — even if
-- it "worked" here, nothing is actually saved.)
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"test@example.com","sub":"AGENT_ID_HERE"}';

  update public.profiles set role = 'admin'
  where id = 'AGENT_ID_HERE'
  returning id, role;
rollback;


-- ---------------------------------------------------------------------
-- CHECK 4 — can a regular (not real, made-up) employee session delete
-- a technical issue? Delete is supposed to be full-admin only.
-- Expect: 0 rows returned.
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"real-employee@example.com","sub":"22222222-2222-2222-2222-222222222222"}';

  delete from public.technical_issues
  where id = (select id from public.technical_issues limit 1)
  returning id;
rollback;


-- ---------------------------------------------------------------------
-- CHECK 5 — using a REAL admin's own id, do they still have full write
-- access? Expect: succeeds and returns the row (sanity check that the
-- lockdown didn't overreach and break admin access too).
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"test@example.com","sub":"ADMIN_ID_HERE"}';

  insert into public.categories (key, label, label_ar, color)
  values ('admin-test-category', 'Admin Test', 'اختبار أدمن', '#00ff00')
  returning key;
rollback;


-- =====================================================================
-- PASS B — run each of these TWO checks on its own. A red error IS
-- the pass. Neither needs the real ids from Step 1.
-- =====================================================================

-- ---------------------------------------------------------------------
-- CHECK 2 (run alone) — can an employee log a technical issue under a
-- COLLEAGUE'S email instead of their own?
-- Expect: RED ERROR "new row violates row-level security policy".
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"real-employee@example.com","sub":"22222222-2222-2222-2222-222222222222"}';

  insert into public.technical_issues (phone_number, issue_type, employee_email)
  values ('TEST-IMPERSONATION', 'audio', 'someone-else@example.com');
rollback;


-- ---------------------------------------------------------------------
-- CHECK 3 (run alone) — can a regular employee (not admin) add a new
-- category, i.e. write to admin-only content?
-- Expect: RED ERROR "new row violates row-level security policy".
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"real-employee@example.com","sub":"22222222-2222-2222-2222-222222222222"}';

  insert into public.categories (key, label, label_ar, color)
  values ('hacker-test', 'Hacker Test', 'اختبار', '#ff0000');
rollback;
