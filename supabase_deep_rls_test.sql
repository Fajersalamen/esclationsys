-- =====================================================================
-- Nova (esclationsys) — Deep RLS security test (v3 — paste and run,
-- no manual editing needed anywhere in this file)
-- =====================================================================
-- Run it in TWO passes:
--   PASS A: CHECK 0 + CHECK 1 + CHECK 4 together. None of these should
--           show a red error — just rows to read.
--   PASS B: run CHECK 2 alone, then CHECK 3 alone, separately from
--           everything else. For THESE TWO, a RED ERROR saying "new
--           row violates row-level security policy" is the correct,
--           good result — running them together with the others would
--           let one real error stop the rest of the script.
--
-- Everything runs inside BEGIN/ROLLBACK — nothing is ever permanently
-- changed. Safe to run on production right now.
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
-- CHECK 1 — is it even POSSIBLE for anyone to update the profiles
-- table (which is where an employee's role lives) from the app side?
-- Expect: ZERO rows back. If this is empty, self-promoting to admin is
-- structurally impossible — there's no rule that allows updating
-- profiles at all, from anyone but you (via the Supabase dashboard).
-- A row appearing here is what you'd need to send me a screenshot of.
-- ---------------------------------------------------------------------
select policyname, cmd, roles, qual as using_expression, with_check as check_expression
from pg_policies
where schemaname = 'public' and tablename = 'profiles' and cmd in ('UPDATE', 'INSERT', 'ALL');


-- ---------------------------------------------------------------------
-- CHECK 4 — can a regular employee delete a technical issue (delete is
-- supposed to be full-admin only)? Expect: 0 rows returned.
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"real-employee@example.com","sub":"22222222-2222-2222-2222-222222222222"}';

  delete from public.technical_issues
  where id = (select id from public.technical_issues limit 1)
  returning id;
rollback;


-- =====================================================================
-- PASS B — run each of these TWO checks on its own. A red error IS
-- the pass.
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
