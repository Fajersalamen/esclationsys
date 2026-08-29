-- =====================================================================
-- Nova (esclationsys) — Force-logout a specific user from Online Users
-- =====================================================================
-- WHY THIS FILE EXISTS
-- Adds a "force logout" button next to each row in the admin's Online
-- Users list. Clicking it signs that person out of every tab they have
-- open, automatically, within one presence heartbeat (~20s) — same
-- "no refresh needed" mechanism as the deleted-user auto-logout and the
-- maintenance-mode kill switch: it just stamps a timestamp on their
-- user_presence row, and their own heartbeat notices it's newer than
-- their current session and signs itself out.
--
-- Logging back in afterward is completely unaffected — a fresh login
-- sets a new, later session_started_at, which is always after
-- whatever force_logout_at was stamped before that login, so the
-- comparison naturally stops matching. Nothing to reset or clean up.
--
-- HOW TO APPLY
-- Run this once in the Supabase project's SQL Editor. Safe to re-run:
-- ADD COLUMN IF NOT EXISTS, and the policy is dropped before being
-- recreated. Assumes supabase_full_security_audit.sql has already
-- been applied (reuses public.is_full_admin()).
-- =====================================================================

alter table public.user_presence
  add column if not exists force_logout_at timestamptz;

-- Only a full admin can force-logout a colleague; nobody can do it to
-- themselves via this policy alone being broad — the UI also just
-- doesn't render the button on the admin's own row.
drop policy if exists "user_presence_update_admin" on public.user_presence;
create policy "user_presence_update_admin" on public.user_presence
  for update using (public.is_full_admin()) with check (public.is_full_admin());

-- Verify: user_presence should now show three UPDATE policies —
-- the pre-existing "own row" one plus this new admin one.
select policyname, cmd, qual as using_expression
from pg_policies
where schemaname = 'public' and tablename = 'user_presence' and cmd = 'UPDATE';
