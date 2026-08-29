-- =====================================================================
-- Nova (esclationsys) — Full penetration test of every table's RLS
-- =====================================================================
-- Run this AFTER applying supabase_full_security_audit.sql. It attacks
-- the database the exact same way a real attacker would: open the
-- browser console on the live site, grab the anon key (it's public by
-- design — that's not the leak), and call the Supabase REST API
-- directly with a real signed-in session, skipping the UI and every
-- client-side "isAdmin" check entirely. Every test below simulates
-- exactly that — a signed-in, completely ordinary employee ("the
-- attacker") trying to do something only RLS can still stop.
--
-- Nothing here permanently changes data: every write attempt runs
-- inside BEGIN/ROLLBACK, and Part A is 100% read-only.
--
-- HOW TO RUN
--   PART A — one single paste-and-run. Every check here is a SELECT,
--            so nothing can throw a hard error; you'll get one result
--            table with a PASS/FAIL row per test. Read it top to
--            bottom — any FAIL is a real, live leak.
--   PART B — each numbered block must be run ALONE (select just that
--            block's SQL and hit Run by itself, not the whole file).
--            Every one of these is EXPECTED to end in a red error
--            reading "new row violates row-level security policy" —
--            that error is the pass. If a block instead succeeds
--            (shows a result row, no error), that is a real hole:
--            screenshot it and send it back.
--
-- Replace the two placeholder emails right below if you want to test
-- with real accounts from your team instead — any two distinct,
-- ordinary (non-admin) employee emails work. The UUIDs don't need to
-- be real signed-up users for this test; RLS only checks the JWT
-- claims, not that the user actually exists.
-- =====================================================================


-- =====================================================================
-- PART A — read-only leak scan across every table (safe to run as one
-- block; every row of output should say PASS)
-- =====================================================================
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"attacker@nova.test","sub":"11111111-1111-1111-1111-111111111111"}';

  select 'suggestions: attacker cannot read the admin-only inbox' as test,
    case when count(*) = 0 then 'PASS' else 'FAIL — attacker can read ' || count(*) || ' suggestion(s)' end as result
  from public.suggestions

  union all
  select 'profiles: attacker sees only their own row (or none)',
    case when count(*) <= 1 then 'PASS' else 'FAIL — attacker can read ' || count(*) || ' profile rows' end
  from public.profiles

  union all
  select 'user_presence: attacker cannot read colleagues'' presence, only their own',
    case when count(*) <= 1 then 'PASS' else 'FAIL — attacker can read ' || count(*) || ' presence rows' end
  from public.user_presence

  union all
  select 'training_problems: attacker sees zero unpublished drafts',
    case when count(*) = 0 then 'PASS' else 'FAIL — attacker can read ' || count(*) || ' draft problem(s)' end
  from public.training_problems where is_active = false

  union all
  select 'training_nodes: attacker sees zero nodes belonging to unpublished problems',
    case when count(*) = 0 then 'PASS' else 'FAIL — attacker can read ' || count(*) || ' draft-linked node(s)' end
  from public.training_nodes where is_active = false

  union all
  select 'training_options: attacker sees zero options of inactive nodes',
    case when count(*) = 0 then 'PASS' else 'FAIL — attacker can read ' || count(*) || ' option(s) of inactive nodes' end
  from public.training_options o
  where exists (select 1 from public.training_nodes n where n.id = o.node_id and n.is_active = false)

  union all
  select 'script_submissions: attacker only sees their own contributions',
    case when count(*) = 0 then 'PASS' else 'FAIL — attacker can read ' || count(*) || ' submission(s) not their own' end
  from public.script_submissions where submitted_by <> 'attacker@nova.test'

  union all
  select 'mentor_requests: attacker only sees requests they''re a party to',
    case when count(*) = 0 then 'PASS' else 'FAIL — attacker can read ' || count(*) || ' request(s) not involving them' end
  from public.mentor_requests
  where trainee_email <> 'attacker@nova.test' and mentor_email <> 'attacker@nova.test'

  union all
  select 'mentor_messages: attacker cannot read threads they''re not part of',
    case when count(*) = 0 then 'PASS' else 'FAIL — attacker can read ' || count(*) || ' message(s) from other threads' end
  from public.mentor_messages m
  where not exists (
    select 1 from public.mentor_requests r
    where r.id = m.request_id
      and (r.trainee_email = 'attacker@nova.test' or r.mentor_email = 'attacker@nova.test')
  )

  union all
  select 'push_subscriptions: attacker cannot read anyone''s push tokens at all',
    case when count(*) = 0 then 'PASS' else 'FAIL — attacker can read ' || count(*) || ' subscription row(s)' end
  from public.push_subscriptions

  union all
  select 'technical_issues: attacker CAN read the shared log (this is intended, not a leak)',
    'INFO — ' || count(*) || ' row(s) visible (by design, every employee reads this log)'
  from public.technical_issues

  union all
  select 'categories/scripts/general_info/critical_items/etiquette_items: readable (intended)',
    'INFO — ' || (
      (select count(*) from public.categories) + (select count(*) from public.scripts) +
      (select count(*) from public.general_info) + (select count(*) from public.critical_items) +
      (select count(*) from public.etiquette_items)
    ) || ' total row(s) visible across content tables (by design)'
rollback;


-- =====================================================================
-- PART B — write-attack tests. RUN EACH BLOCK ALONE. A red RLS error
-- is the correct, good outcome for every single one of these.
-- =====================================================================

-- ---------------------------------------------------------------------
-- B1 — impersonation: log a technical issue under a colleague's email
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"attacker@nova.test","sub":"11111111-1111-1111-1111-111111111111"}';
  insert into public.technical_issues (phone_number, issue_type, employee_email)
  values ('PENTEST', 'audio', 'someone-else@nova.test');
rollback;

-- ---------------------------------------------------------------------
-- B2 — delete a technical issue (delete is full-admin only)
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"attacker@nova.test","sub":"11111111-1111-1111-1111-111111111111"}';
  delete from public.technical_issues where id = (select id from public.technical_issues limit 1) returning id;
rollback;

-- ---------------------------------------------------------------------
-- B3 — write admin-only content directly (add a fake category)
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"attacker@nova.test","sub":"11111111-1111-1111-1111-111111111111"}';
  insert into public.categories (key, label, label_ar, color) values ('pentest', 'Pentest', 'اختبار', '#ff0000');
rollback;

-- ---------------------------------------------------------------------
-- B4 — self-promote to admin by editing your own profile row
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"attacker@nova.test","sub":"11111111-1111-1111-1111-111111111111"}';
  update public.profiles set role = 'admin' where id = '11111111-1111-1111-1111-111111111111';
rollback;

-- ---------------------------------------------------------------------
-- B5 — submit a suggestion under a colleague's name
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"attacker@nova.test","sub":"11111111-1111-1111-1111-111111111111"}';
  insert into public.suggestions (name, text) values ('someone-else@nova.test', 'PENTEST');
rollback;

-- ---------------------------------------------------------------------
-- B6 — submit a script contribution under a colleague's email
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"attacker@nova.test","sub":"11111111-1111-1111-1111-111111111111"}';
  insert into public.script_submissions (cat, title, text, submitted_by)
  values ('general', 'PENTEST', 'PENTEST', 'someone-else@nova.test');
rollback;

-- ---------------------------------------------------------------------
-- B7 — approve your own script contribution (approve/reject is
-- admin/team_leader only)
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"attacker@nova.test","sub":"11111111-1111-1111-1111-111111111111"}';
  insert into public.script_submissions (cat, title, text, submitted_by)
  values ('general', 'PENTEST', 'PENTEST', 'attacker@nova.test') returning id;
  -- (if the insert above succeeded — which it should, it's your own —
  -- this update is the actual attack, and THIS is the line that must error)
  update public.script_submissions set status = 'approved'
  where submitted_by = 'attacker@nova.test' and title = 'PENTEST';
rollback;

-- ---------------------------------------------------------------------
-- B8 — file a mentorship request pretending to be someone else's
-- trainee (spoof trainee_email)
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"attacker@nova.test","sub":"11111111-1111-1111-1111-111111111111"}';
  insert into public.mentor_requests (trainee_email, mentor_email) values ('someone-else@nova.test', 'mentor@nova.test');
rollback;

-- ---------------------------------------------------------------------
-- B9 — accept/decline a mentorship request you were not the invited
-- mentor on (fixture request created inline, as superuser, before the
-- role switch, then attacked)
-- ---------------------------------------------------------------------
begin;
  insert into public.mentor_requests (trainee_email, mentor_email, status)
  values ('pentest-trainee@nova.test', 'pentest-mentor@nova.test', 'pending');

  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"attacker@nova.test","sub":"11111111-1111-1111-1111-111111111111"}';
  update public.mentor_requests set status = 'accepted'
  where trainee_email = 'pentest-trainee@nova.test' and mentor_email = 'pentest-mentor@nova.test';
rollback;

-- ---------------------------------------------------------------------
-- B10 — THE FIX FROM supabase_full_security_audit.sql: message in your
-- own mentorship request BEFORE the mentor has accepted it. The chat
-- UI only ever shows the send box once status = 'accepted' — this
-- proves the database enforces that too, not just the UI.
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"attacker@nova.test","sub":"11111111-1111-1111-1111-111111111111"}';
  with fresh_request as (
    insert into public.mentor_requests (trainee_email, mentor_email, status)
    values ('attacker@nova.test', 'some-mentor@nova.test', 'pending')
    returning id
  )
  insert into public.mentor_messages (request_id, sender_email, text)
  select id, 'attacker@nova.test', 'PENTEST: message before acceptance' from fresh_request;
rollback;

-- ---------------------------------------------------------------------
-- B11 — message into an accepted thread between two OTHER people you
-- are not a participant in (fixture created inline as superuser)
-- ---------------------------------------------------------------------
begin;
  insert into public.mentor_requests (trainee_email, mentor_email, status)
  values ('pentest-victim-a@nova.test', 'pentest-victim-b@nova.test', 'accepted');

  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"attacker@nova.test","sub":"11111111-1111-1111-1111-111111111111"}';
  insert into public.mentor_messages (request_id, sender_email, text)
  select id, 'attacker@nova.test', 'PENTEST: uninvited message'
  from public.mentor_requests
  where trainee_email = 'pentest-victim-a@nova.test' and mentor_email = 'pentest-victim-b@nova.test';
rollback;

-- ---------------------------------------------------------------------
-- B12 — register a push subscription under a colleague's email
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"attacker@nova.test","sub":"11111111-1111-1111-1111-111111111111"}';
  insert into public.push_subscriptions (user_email, endpoint, p256dh, auth)
  values ('someone-else@nova.test', 'https://pentest.example/endpoint', 'x', 'y');
rollback;

-- ---------------------------------------------------------------------
-- B13 — write to training content directly (admin-only)
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"attacker@nova.test","sub":"11111111-1111-1111-1111-111111111111"}';
  insert into public.training_problems (title, title_ar, is_active) values ('PENTEST', 'اختبار', true);
rollback;

-- ---------------------------------------------------------------------
-- B14 — post an update to the "New Updates" feed directly (admin-only)
-- ---------------------------------------------------------------------
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"role":"authenticated","email":"attacker@nova.test","sub":"11111111-1111-1111-1111-111111111111"}';
  insert into public.updates (text) values ('PENTEST');
rollback;


-- =====================================================================
-- HOW TO READ THE RESULTS
--   Part A: every row should say PASS, except the two INFO rows (those
--     tables are meant to be broadly readable — that's correct).
--   Part B: every block should end in a red error containing "row-level
--     security policy". If ANY block instead completes successfully
--     (you see a normal result, no red error), screenshot exactly that
--     block and send it — that is a live, exploitable hole and needs a
--     policy fix, not a "nice to have."
-- =====================================================================
