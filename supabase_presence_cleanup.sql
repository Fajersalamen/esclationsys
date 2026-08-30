-- =====================================================================
-- Nova (esclationsys) — Stop deleted users from lingering in Online Users
-- =====================================================================
-- WHY THIS FILE EXISTS
-- A user_presence row is keyed by user_id, but nothing was ever set up
-- to remove that row when the underlying account gets deleted from
-- auth.users. The row just sits there forever with whatever last_seen
-- it had at the moment of deletion. Reported symptom: a deleted
-- employee kept flickering "Online / Offline" in the admin's Online
-- Users list even though they have no email/password to ever sign in
-- again.
--
-- What was actually happening: force-logout (or the deleted-account
-- auto-logout) only affects an ALREADY-SIGNED-IN session — it can't
-- undo a session that was open on another device, or one that keeps
-- reconnecting on some interval you don't control. But once someone is
-- genuinely deleted from auth.users, there is no legitimate way for
-- ANY session of theirs to still be sending real heartbeats — so a
-- lingering, flapping row for a deleted account is the row itself
-- being stale/orphaned, not a real live session. This trigger removes
-- that row the moment the account is deleted, so it simply disappears
-- from the list instead of sitting there in a confusing half-state.
--
-- This does not rely on (or touch) any existing foreign key on
-- user_presence.user_id, since its exact name/definition isn't known
-- from this repo's history (the table predates the SQL files tracked
-- here) — a trigger on auth.users is used instead, which works
-- regardless of whatever constraints already exist.
--
-- HOW TO APPLY
-- Run this once in the Supabase project's SQL Editor. Safe to re-run.
-- =====================================================================

create or replace function public.cleanup_presence_on_user_delete()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.user_presence where user_id = old.id;
  return old;
end;
$$;

drop trigger if exists trg_cleanup_presence_on_user_delete on auth.users;
create trigger trg_cleanup_presence_on_user_delete
  after delete on auth.users
  for each row execute function public.cleanup_presence_on_user_delete();

-- One-time cleanup: remove any already-orphaned rows left over from
-- accounts deleted before this trigger existed (this is what actually
-- fixes the flickering row you're seeing right now).
delete from public.user_presence
where user_id not in (select id from auth.users);

-- Verify: should return 0.
select count(*) as remaining_orphaned_rows
from public.user_presence
where user_id not in (select id from auth.users);
