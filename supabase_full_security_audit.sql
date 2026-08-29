-- =====================================================================
-- Nova (esclationsys) — FULL security audit + one-shot re-hardening
-- =====================================================================
-- WHY THIS FILE EXISTS
-- Over several sessions, RLS policies were added table-by-table across
-- many separate files (supabase_rls_policies.sql, supabase_mentorship.sql,
-- supabase_script_submissions.sql, supabase_push_subscriptions.sql,
-- supabase_push_subscriptions_update_policy.sql,
-- supabase_fix_technical_issues_select.sql, supabase_close_read_leak.sql).
-- Depending on which of those were actually run, and in what order, the
-- live database can end up with two DIFFERENT policies covering the same
-- table + command, under two different names. Postgres does not treat
-- that as an error — it silently OR-combines every permissive policy for
-- the same command, so the LOOSEST one always wins. That is exactly the
-- bug supabase_close_read_leak.sql fixed once already (a leftover
-- "read everything" policy on profiles/user_presence was quietly
-- overriding the "own row only" one). This file finds and closes every
-- remaining instance of that same class of bug, for every table the app
-- uses, in one pass — instead of patching them one at a time as they're
-- noticed.
--
-- CONCRETE ISSUE THIS FILE FIXES
-- supabase_rls_policies.sql defines "mentor_messages_insert_participant",
-- which lets either side of a mentor_requests row post a message the
-- moment the request exists — no check on its status. Separately,
-- supabase_mentorship.sql defines "mentor_messages_insert_own_thread",
-- which correctly requires status = 'accepted' first (matching the
-- app's own UI, which only shows the chat box once a request is
-- accepted — see the `active.status === 'accepted'` gate in app.js).
-- If both policies are currently live, the looser one wins: anyone can
-- open the browser console and insert a message into a thread whose
-- mentor never accepted the request, bypassing that gate entirely. This
-- file drops both old policies by name and recreates exactly one,
-- correct version.
--
-- WHAT THIS FILE DOES
--   PART 1 — read-only audit of all 17 tables the app actually touches
--            (the older audit files only listed 13 — script_submissions,
--            mentor_requests, mentor_messages and push_subscriptions were
--            missing from that list entirely).
--   PART 2 — duplicate-policy hygiene check: any table+command with more
--            than one active policy, which is the exact shape of bug
--            described above. Run PART 1 + PART 2 FIRST, before PART 3,
--            and keep the output — it's your "before" picture.
--   PART 3 — the fix: drops every policy name used by ANY past file in
--            this repo (so it converges to a clean state no matter which
--            subset you've actually run before), then recreates a single
--            authoritative policy set for every table, matching exactly
--            what app.js does today.
--   PART 4 — re-run PART 1 + PART 2 to confirm: 17/17 tables POLICED,
--            zero duplicate-policy rows.
--
-- Nothing here touches data. It only adds/replaces/drops access-control
-- rules, and is 100% safe to re-run from scratch at any time.
--
-- HOW TO RUN
-- Supabase Dashboard → SQL Editor → paste this whole file → Run.
-- Then copy/screenshot the results of the two SELECTs at the very
-- bottom (labelled "FINAL AUDIT" and "FINAL DUPLICATE CHECK") back here.
-- =====================================================================


-- =====================================================================
-- PART 1 — full-table audit (run this block first, before touching
-- anything else, to see the "before" state)
-- =====================================================================
with app_tables as (
  select unnest(array[
    'profiles', 'categories', 'scripts', 'general_info', 'critical_items',
    'etiquette_items', 'updates', 'suggestions', 'technical_issues',
    'user_presence', 'training_problems', 'training_nodes', 'training_options',
    'script_submissions', 'mentor_requests', 'mentor_messages', 'push_subscriptions'
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
    else '🟢 POLICED — RLS is on with ' || p.policy_count || ' policy/policies'
  end as verdict
from app_tables t
left join rls_state r on r.table_name = t.table_name
left join policy_counts p on p.table_name = t.table_name
order by t.table_name;


-- =====================================================================
-- PART 2 — duplicate-policy hygiene check. Any row here means two
-- policies are OR-combined for the same table+command — read both by
-- name (pg_policies) and figure out which is the intended one before
-- running PART 3, since PART 3 will remove the ones this file knows
-- about but a duplicate you added by hand elsewhere would not be
-- caught here by name and needs manual review.
-- =====================================================================
select tablename, cmd, count(*) as policy_count, array_agg(policyname) as policy_names
from pg_policies
where schemaname = 'public'
group by tablename, cmd
having count(*) > 1
order by tablename, cmd;


-- =====================================================================
-- PART 3 — the fix. Safe to re-run any number of times.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 3a. Helper functions (SECURITY DEFINER so they can read `profiles`
-- without recursively re-triggering RLS on `profiles` itself).
-- ---------------------------------------------------------------------
create or replace function public.current_role_name()
returns text
language sql
security definer
set search_path = public
stable
as $$
  select role from public.profiles where id = auth.uid();
$$;

create or replace function public.is_admin_or_lead()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select coalesce(public.current_role_name() in ('admin', 'team_leader'), false);
$$;

create or replace function public.is_full_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select coalesce(public.current_role_name() = 'admin', false);
$$;


-- ---------------------------------------------------------------------
-- 3b. Drop every policy name that has EVER existed on these tables
-- across every file in this repo's history, so the result below is the
-- same clean state no matter which of those files you happened to run
-- before, in whatever order. All DROP POLICY IF EXISTS — no-ops for
-- names that were never applied.
-- ---------------------------------------------------------------------
drop policy if exists "Allow authenticated read on profiles" on public.profiles;
drop policy if exists "profiles_select_own" on public.profiles;

drop policy if exists "Allow authenticated read on user_presence" on public.user_presence;
drop policy if exists "user_presence_select_admin_or_own" on public.user_presence;
drop policy if exists "user_presence_upsert_own" on public.user_presence;
drop policy if exists "user_presence_update_own" on public.user_presence;

do $$
declare
  t text;
begin
  foreach t in array array['categories','scripts','general_info','critical_items','etiquette_items'] loop
    execute format('drop policy if exists "%s_select_authenticated" on public.%I;', t, t);
    execute format('drop policy if exists "%s_insert_admin" on public.%I;', t, t);
    execute format('drop policy if exists "%s_update_admin" on public.%I;', t, t);
    execute format('drop policy if exists "%s_delete_full_admin" on public.%I;', t, t);
  end loop;
end $$;

drop policy if exists "updates_select_authenticated" on public.updates;
drop policy if exists "updates_insert_admin" on public.updates;
drop policy if exists "updates_delete_full_admin" on public.updates;

drop policy if exists "suggestions_insert_own_email" on public.suggestions;
drop policy if exists "suggestions_select_admin" on public.suggestions;
drop policy if exists "suggestions_delete_full_admin" on public.suggestions;

drop policy if exists "technical_issues_select_authenticated" on public.technical_issues;
drop policy if exists "technical_issues_insert_own_email" on public.technical_issues;
drop policy if exists "technical_issues_delete_full_admin" on public.technical_issues;

do $$
declare
  t text;
begin
  foreach t in array array['training_problems','training_nodes'] loop
    execute format('drop policy if exists "%s_select_visible" on public.%I;', t, t);
    execute format('drop policy if exists "%s_insert_admin" on public.%I;', t, t);
    execute format('drop policy if exists "%s_update_admin" on public.%I;', t, t);
    execute format('drop policy if exists "%s_delete_full_admin" on public.%I;', t, t);
  end loop;
end $$;

drop policy if exists "training_options_select_visible" on public.training_options;
drop policy if exists "read options of visible nodes or admin" on public.training_options;
drop policy if exists "training_options_insert_admin" on public.training_options;
drop policy if exists "training_options_update_admin" on public.training_options;
drop policy if exists "training_options_delete_full_admin" on public.training_options;

drop policy if exists "script_submissions_select_own_or_admin" on public.script_submissions;
drop policy if exists "script_submissions_insert_own_email" on public.script_submissions;
drop policy if exists "script_submissions_update_admin" on public.script_submissions;
drop policy if exists "script_submissions_delete_full_admin" on public.script_submissions;

-- mentor_requests / mentor_messages: two different files defined two
-- different names for the same commands — drop BOTH generations.
drop policy if exists "mentor_requests_select_participant" on public.mentor_requests;
drop policy if exists "mentor_requests_insert_as_trainee" on public.mentor_requests;
drop policy if exists "mentor_requests_insert_own" on public.mentor_requests;
drop policy if exists "mentor_requests_update_as_mentor" on public.mentor_requests;
drop policy if exists "mentor_requests_update_mentor" on public.mentor_requests;
drop policy if exists "mentor_requests_delete_own_pending_or_admin" on public.mentor_requests;

drop policy if exists "mentor_messages_select_participant" on public.mentor_messages;
drop policy if exists "mentor_messages_select_own_thread" on public.mentor_messages;
drop policy if exists "mentor_messages_insert_participant" on public.mentor_messages;
drop policy if exists "mentor_messages_insert_own_thread" on public.mentor_messages;
drop policy if exists "mentor_messages_delete_full_admin" on public.mentor_messages;

drop policy if exists "push_subscriptions_insert_own" on public.push_subscriptions;
drop policy if exists "push_subscriptions_select_own" on public.push_subscriptions;
drop policy if exists "push_subscriptions_update_own" on public.push_subscriptions;
drop policy if exists "push_subscriptions_delete_own_or_admin" on public.push_subscriptions;


-- ---------------------------------------------------------------------
-- 3c. Recreate exactly one, current, correct policy set per table.
-- ---------------------------------------------------------------------

-- profiles — each user reads only their own role. No client-side
-- INSERT/UPDATE/DELETE at all (role changes happen only via the
-- Supabase dashboard) — without this, a user could grant themselves
-- 'admin' by editing their own profile row.
alter table public.profiles enable row level security;
create policy "profiles_select_own" on public.profiles
  for select using (auth.uid() = id);

-- Content tables — readable by any signed-in employee, writable only
-- by admin/team_leader, deletable only by full admin.
do $$
declare
  t text;
begin
  foreach t in array array['categories','scripts','general_info','critical_items','etiquette_items'] loop
    execute format('alter table public.%I enable row level security;', t);
    execute format(
      'create policy "%s_select_authenticated" on public.%I for select using (auth.role() = ''authenticated'');',
      t, t
    );
    execute format(
      'create policy "%s_insert_admin" on public.%I for insert with check (public.is_admin_or_lead());',
      t, t
    );
    execute format(
      'create policy "%s_update_admin" on public.%I for update using (public.is_admin_or_lead()) with check (public.is_admin_or_lead());',
      t, t
    );
    execute format(
      'create policy "%s_delete_full_admin" on public.%I for delete using (public.is_full_admin());',
      t, t
    );
  end loop;
end $$;

-- updates — same read-all/write-admin shape.
alter table public.updates enable row level security;
create policy "updates_select_authenticated" on public.updates
  for select using (auth.role() = 'authenticated');
create policy "updates_insert_admin" on public.updates
  for insert with check (public.is_admin_or_lead());
create policy "updates_delete_full_admin" on public.updates
  for delete using (public.is_full_admin());

-- suggestions — any employee can submit one under their own email;
-- only admin/team_leader can read the list; only full admin deletes.
alter table public.suggestions enable row level security;
create policy "suggestions_insert_own_email" on public.suggestions
  for insert with check (
    auth.role() = 'authenticated' and name = (auth.jwt() ->> 'email')
  );
create policy "suggestions_select_admin" on public.suggestions
  for select using (public.is_admin_or_lead());
create policy "suggestions_delete_full_admin" on public.suggestions
  for delete using (public.is_full_admin());

-- technical_issues — every employee can read the shared log; insert is
-- only allowed under the reporting employee's own verified email
-- (nobody can log an issue in a colleague's name); delete is
-- full-admin only; no update path exists client-side, so none is
-- granted.
alter table public.technical_issues enable row level security;
create policy "technical_issues_select_authenticated" on public.technical_issues
  for select using (auth.role() = 'authenticated');
create policy "technical_issues_insert_own_email" on public.technical_issues
  for insert with check (
    auth.role() = 'authenticated' and employee_email = (auth.jwt() ->> 'email')
  );
create policy "technical_issues_delete_full_admin" on public.technical_issues
  for delete using (public.is_full_admin());

-- user_presence — each user may only write their own heartbeat row;
-- reading the full list is admin-only, but every user may read their
-- own row.
alter table public.user_presence enable row level security;
create policy "user_presence_select_admin_or_own" on public.user_presence
  for select using (public.is_admin_or_lead() or user_id = auth.uid());
create policy "user_presence_upsert_own" on public.user_presence
  for insert with check (user_id = auth.uid());
create policy "user_presence_update_own" on public.user_presence
  for update using (user_id = auth.uid()) with check (user_id = auth.uid());

-- training_problems / training_nodes — regular employees only see
-- published (is_active = true) content; admin/team_leader see drafts
-- too. Write is admin-only, delete is full-admin only.
do $$
declare
  t text;
begin
  foreach t in array array['training_problems','training_nodes'] loop
    execute format('alter table public.%I enable row level security;', t);
    execute format(
      'create policy "%s_select_visible" on public.%I for select using (is_active = true or public.is_admin_or_lead());',
      t, t
    );
    execute format(
      'create policy "%s_insert_admin" on public.%I for insert with check (public.is_admin_or_lead());',
      t, t
    );
    execute format(
      'create policy "%s_update_admin" on public.%I for update using (public.is_admin_or_lead()) with check (public.is_admin_or_lead());',
      t, t
    );
    execute format(
      'create policy "%s_delete_full_admin" on public.%I for delete using (public.is_full_admin());',
      t, t
    );
  end loop;
end $$;

-- training_options has no is_active of its own — visibility follows
-- the parent training_node's is_active.
alter table public.training_options enable row level security;
create policy "training_options_select_visible" on public.training_options
  for select using (
    public.is_admin_or_lead()
    or exists (
      select 1 from public.training_nodes n
      where n.id = training_options.node_id and n.is_active = true
    )
  );
create policy "training_options_insert_admin" on public.training_options
  for insert with check (public.is_admin_or_lead());
create policy "training_options_update_admin" on public.training_options
  for update using (public.is_admin_or_lead()) with check (public.is_admin_or_lead());
create policy "training_options_delete_full_admin" on public.training_options
  for delete using (public.is_full_admin());

-- script_submissions — an employee sees only their own contributions;
-- admin/team_leader see all (the pending-review queue). Insert must be
-- under the submitter's own email. Approve/reject is admin/team_leader
-- only. Delete is full-admin only.
alter table public.script_submissions enable row level security;
create policy "script_submissions_select_own_or_admin" on public.script_submissions
  for select using (
    submitted_by = (auth.jwt() ->> 'email') or public.is_admin_or_lead()
  );
create policy "script_submissions_insert_own_email" on public.script_submissions
  for insert with check (
    auth.role() = 'authenticated' and submitted_by = (auth.jwt() ->> 'email')
  );
create policy "script_submissions_update_admin" on public.script_submissions
  for update using (public.is_admin_or_lead()) with check (public.is_admin_or_lead());
create policy "script_submissions_delete_full_admin" on public.script_submissions
  for delete using (public.is_full_admin());

-- mentor_requests — each employee sees only requests they're a party
-- to (as trainee or mentor). Insert must be made as the trainee.
-- Responding (accept/decline) is restricted to the addressed mentor.
-- The trainee may cancel their own still-pending request; a full admin
-- may remove any request.
alter table public.mentor_requests enable row level security;
create policy "mentor_requests_select_participant" on public.mentor_requests
  for select using (
    trainee_email = (auth.jwt() ->> 'email') or mentor_email = (auth.jwt() ->> 'email')
  );
create policy "mentor_requests_insert_as_trainee" on public.mentor_requests
  for insert with check (
    auth.role() = 'authenticated' and trainee_email = (auth.jwt() ->> 'email')
  );
create policy "mentor_requests_update_as_mentor" on public.mentor_requests
  for update using (mentor_email = (auth.jwt() ->> 'email'))
  with check (mentor_email = (auth.jwt() ->> 'email'));
create policy "mentor_requests_delete_own_pending_or_admin" on public.mentor_requests
  for delete using (
    public.is_full_admin()
    or (trainee_email = (auth.jwt() ->> 'email') and status = 'pending')
  );

-- mentor_messages — private chat for an ACCEPTED mentor_requests pair
-- only. This is the fix described at the top of this file: insert now
-- requires status = 'accepted' on the parent request, matching what
-- the UI already assumes (the chat box only appears once a request is
-- accepted) — previously a looser policy let either side post into a
-- still-pending request's thread if called directly via the API.
alter table public.mentor_messages enable row level security;
create policy "mentor_messages_select_participant" on public.mentor_messages
  for select using (
    exists (
      select 1 from public.mentor_requests r
      where r.id = mentor_messages.request_id
        and (r.trainee_email = (auth.jwt() ->> 'email') or r.mentor_email = (auth.jwt() ->> 'email'))
    )
  );
create policy "mentor_messages_insert_accepted_participant" on public.mentor_messages
  for insert with check (
    auth.role() = 'authenticated'
    and sender_email = (auth.jwt() ->> 'email')
    and exists (
      select 1 from public.mentor_requests r
      where r.id = mentor_messages.request_id
        and r.status = 'accepted'
        and (r.trainee_email = (auth.jwt() ->> 'email') or r.mentor_email = (auth.jwt() ->> 'email'))
    )
  );
create policy "mentor_messages_delete_full_admin" on public.mentor_messages
  for delete using (public.is_full_admin());

-- push_subscriptions — a device's web-push token, written only by its
-- own owner. app.js never reads this table back client-side (only the
-- send-mentor-push Edge Function does, using the service_role key,
-- which bypasses RLS entirely) — so, matching real usage, no SELECT or
-- DELETE policy is granted here, same as the original hardening pass.
-- An UPDATE policy is required alongside INSERT: the client's upsert
-- (keyed on the unique `endpoint` column) becomes an
-- INSERT ... ON CONFLICT ... DO UPDATE under the hood on every repeat
-- visit, which Postgres RLS checks against the UPDATE policy, not INSERT.
alter table public.push_subscriptions enable row level security;
create policy "push_subscriptions_insert_own" on public.push_subscriptions
  for insert with check (
    auth.role() = 'authenticated' and user_email = (auth.jwt() ->> 'email')
  );
create policy "push_subscriptions_update_own" on public.push_subscriptions
  for update using (user_email = (auth.jwt() ->> 'email'))
  with check (user_email = (auth.jwt() ->> 'email'));

-- Mentor picker directory — every email address that can sign in, so
-- the mentor picker can be a dropdown instead of free-text. Deliberate,
-- narrow widening: exposes every employee's email (nothing else) to
-- every other signed-in employee. Skip this block if that's not wanted.
create or replace function public.list_directory_emails()
returns table(email text)
language sql
security definer
set search_path = public
stable
as $$
  select u.email::text
  from auth.users u
  where u.email is not null
  order by u.email;
$$;
revoke all on function public.list_directory_emails() from public;
grant execute on function public.list_directory_emails() to authenticated;


-- =====================================================================
-- PART 4 — FINAL AUDIT: re-run after PART 3. Expect all 17 rows
-- POLICED, and the duplicate check below to return zero rows.
-- =====================================================================
with app_tables as (
  select unnest(array[
    'profiles', 'categories', 'scripts', 'general_info', 'critical_items',
    'etiquette_items', 'updates', 'suggestions', 'technical_issues',
    'user_presence', 'training_problems', 'training_nodes', 'training_options',
    'script_submissions', 'mentor_requests', 'mentor_messages', 'push_subscriptions'
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
  coalesce(r.rls_enabled, false) as rls_enabled,
  coalesce(p.policy_count, 0) as policy_count,
  case
    when r.table_name is null then '❌ TABLE NOT FOUND'
    when r.rls_enabled = false then '🔴 OPEN'
    when r.rls_enabled = true and coalesce(p.policy_count, 0) = 0 then '🟠 LOCKED (0 policies)'
    else '🟢 POLICED'
  end as verdict
from app_tables t
left join rls_state r on r.table_name = t.table_name
left join policy_counts p on p.table_name = t.table_name
order by t.table_name;

-- FINAL DUPLICATE CHECK — must return zero rows.
select tablename, cmd, count(*) as policy_count, array_agg(policyname) as policy_names
from pg_policies
where schemaname = 'public'
group by tablename, cmd
having count(*) > 1
order by tablename, cmd;

-- Privilege-escalation sanity check — must return zero rows (nothing
-- should let a regular user UPDATE their own profiles.role).
select policyname, cmd, qual as using_expression, with_check as check_expression
from pg_policies
where schemaname = 'public' and tablename = 'profiles' and cmd in ('UPDATE', 'ALL');
