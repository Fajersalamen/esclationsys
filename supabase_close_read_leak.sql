-- =====================================================================
-- Nova (esclationsys) — URGENT: close a live read-access leak
-- =====================================================================
-- Found via a live audit of the production policy list: two leftover
-- policies from before the RLS hardening pass are still active and
-- grant broad read access, silently overriding the intended
-- "own row only" / "admin only" restrictions (Postgres combines
-- multiple permissive policies for the same command with OR — the
-- loosest one wins).
--
--   1. "Allow authenticated read on profiles" lets ANY signed-in
--      employee read every row of `profiles`, i.e. every employee's
--      role (who's admin/team_leader/etc), not just their own row.
--   2. "Allow authenticated read on user_presence" lets ANY signed-in
--      employee read the full presence table (who's online, last
--      seen, login time, for every employee) — meant to be admin-only.
--
-- Verified against app.js: nothing in the app relies on the broad
-- read in either case (profiles is only ever fetched by your own id;
-- the full user_presence list is only ever fetched when isAdmin is
-- true client-side). Dropping these is safe and does not break
-- anything — it only removes access nothing legitimate was using.
--
-- Also tightens training_nodes/training_options: the newer SELECT
-- policies only check the node/option's own is_active flag, not its
-- parent training_problem's is_active — so a node belonging to an
-- unpublished (draft) problem could still leak to regular employees.
-- The older policies already check the full chain correctly, so we
-- just drop the newer, looser duplicates and keep the correct ones.
--
-- Safe to re-run. Uses IF EXISTS, so re-running after it's already
-- applied is a no-op.
-- =====================================================================

drop policy if exists "Allow authenticated read on profiles" on public.profiles;
drop policy if exists "Allow authenticated read on user_presence" on public.user_presence;
drop policy if exists "training_nodes_select_visible" on public.training_nodes;
drop policy if exists "training_options_select_visible" on public.training_options;

-- ---------------------------------------------------------------------
-- Verify: each of these four should now show exactly the policies
-- listed after the arrow, nothing else, for SELECT.
-- ---------------------------------------------------------------------
select tablename, policyname, cmd, qual as using_expression
from pg_policies
where schemaname = 'public'
  and tablename in ('profiles', 'user_presence', 'training_nodes', 'training_options')
  and cmd = 'SELECT'
order by tablename, policyname;

-- profiles         -> only "profiles_select_own"                (auth.uid() = id)
-- user_presence    -> only "user_presence_select_admin_or_own"  (is_admin_or_lead() OR user_id = auth.uid())
-- training_nodes   -> only "read active nodes or admin"         (chain-checked is_active OR admin)
-- training_options -> only "read options of visible nodes or admin" (chain-checked is_active OR admin)
