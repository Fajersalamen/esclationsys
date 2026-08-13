-- =====================================================================
-- Nova (esclationsys) — Deep RLS security test
-- =====================================================================
-- Everything below runs inside BEGIN/ROLLBACK, including the fake test
-- profiles it creates — nothing is ever actually saved, and no real
-- employee data is touched. Safe to run on production right now.
--
-- IMPORTANT — run it in TWO passes, not all at once:
--   PASS A: select CHECK 0 + CHECK 1 + CHECK 4 + CHECK 5 together (or
--           one at a time) and hit Run. None of these should show a
--           red error — they just return rows to read.
--   PASS B: run CHECK 2 by itself, then CHECK 3 by itself (separately
--           from everything else). For THESE TWO, seeing a RED ERROR
--           saying "new row violates row-level security policy" is
--           the correct, good result — it means the block worked. If
--           you ran them together with the others, one real error
--           would stop the rest of the script from running at all
--           (that's exactly what caused the last incident), so keep
--           them isolated.
--
-- Screenshot me the result of each check and I'll read the verdicts.
-- =====================================================================


-- ---------------------------------------------------------------------
-- CHECK 0 — policy hygiene: does any table have more than one policy
-- for the same command? (Leftover/duplicate policies from earlier
-- partial script runs can silently widen access, since Postgres OR's
-- multiple policies for the same command together.)
-- Expect ZERO rows back. Any row returned = send me a screenshot.
-- ---------------------------------------------------------------------
select tablename, cmd, count(*) as policy_count,
       array_agg(policyname) as policy_names
from pg_policies
where schemaname = 'public'
group by tablename, cmd
having count(*) > 1
order by tablename, cmd;


-- ---------------------------------------------------------------------
-- CHECK 1 — can a regular employee promote themselves to admin by
-- editing their own profile row? The single most dangerous possible
-- hole. Uses a temporary fake profile, destroyed by the rollback.
-- Expect: 0 rows returned. A row showing role = 'admin' = CRITICAL bug.
-- ---------------------------------------------------------------------
begin;
  insert into public.profiles (id, role)
  values ('11111111-1111-1111-1111-111111111111', 'agent')
  on conflict (id) do update set role = 'agent';

  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"test-agent@example.com","sub":"11111111-1111-1111-1111-111111111111"}';

  update public.profiles set role = 'admin'
  where id = '11111111-1111-1111-1111-111111111111'
  returning id, role;
rollback;


-- ---------------------------------------------------------------------
-- CHECK 4 — can a regular employee delete a technical issue (delete is
-- supposed to be full-admin only)?
-- Expect: 0 rows returned. A row coming back = employees can delete
-- records they shouldn't be able to.
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"real-employee@example.com","sub":"22222222-2222-2222-2222-222222222222"}';

  delete from public.technical_issues
  where id = (select id from public.technical_issues limit 1)
  returning id;
rollback;


-- ---------------------------------------------------------------------
-- CHECK 5 — sanity check the other direction: does a REAL admin still
-- have full access? Uses a temporary fake admin profile, destroyed by
-- the rollback — does not touch any real account or data.
-- Expect: succeeds and returns the row.
-- ---------------------------------------------------------------------
begin;
  insert into public.profiles (id, role)
  values ('33333333-3333-3333-3333-333333333333', 'admin')
  on conflict (id) do update set role = 'admin';

  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"test-admin@example.com","sub":"33333333-3333-3333-3333-333333333333"}';

  insert into public.categories (key, label, label_ar, color)
  values ('admin-test-category', 'Admin Test', 'اختبار أدمن', '#00ff00')
  returning key;
rollback;


-- =====================================================================
-- PASS B — run each of these TWO checks on its own, separately from
-- everything above and from each other. A red error IS the pass.
-- =====================================================================

-- ---------------------------------------------------------------------
-- CHECK 2 (run alone) — can an employee log a technical issue under a
-- COLLEAGUE'S email instead of their own?
-- Expect: RED ERROR "new row violates row-level security policy" =
-- correctly blocked, this is good. If it succeeds instead, that's a bug.
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
-- Expect: RED ERROR "new row violates row-level security policy" =
-- correctly blocked, this is good. If it succeeds instead, that's a bug.
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"real-employee@example.com","sub":"22222222-2222-2222-2222-222222222222"}';

  insert into public.categories (key, label, label_ar, color)
  values ('hacker-test', 'Hacker Test', 'اختبار', '#ff0000');
rollback;
