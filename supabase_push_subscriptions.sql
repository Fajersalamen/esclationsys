-- =====================================================================
-- Nova (esclationsys) — Push notification subscriptions
-- =====================================================================
-- WHY THIS FILE EXISTS
-- Stores each browser's Web Push subscription (one row per device/
-- browser a user granted notification permission on), so a server-side
-- function can later push a real OS notification to that device even
-- when the site isn't open — unlike the in-app "New Updates" sound,
-- which only fires while the tab is open and polling.
--
-- This table alone does not send anything. It's just where the client
-- stores subscriptions; the actual push-sending happens in the
-- send-mentor-push Supabase Edge Function (see supabase/functions/),
-- triggered by a Database Webhook on mentor_messages INSERT. See the
-- deployment checklist sent alongside this file for the remaining
-- setup steps (those can't be done via SQL alone).
--
-- HOW TO APPLY
-- Run this once in the Supabase project's SQL Editor. Safe to re-run:
-- CREATE TABLE IF NOT EXISTS, and each policy is dropped before being
-- recreated. Assumes supabase_rls_policies.sql has already been
-- applied.
-- =====================================================================

create table if not exists public.push_subscriptions (
  id bigint generated always as identity primary key,
  user_email text not null,
  endpoint text not null unique,
  p256dh text not null,
  auth text not null,
  created_at timestamptz not null default now()
);

alter table public.push_subscriptions enable row level security;

-- A user can only ever register a subscription under their own email.
drop policy if exists "push_subscriptions_insert_own" on public.push_subscriptions;
create policy "push_subscriptions_insert_own" on public.push_subscriptions
  for insert with check (
    auth.role() = 'authenticated'
    and user_email = (auth.jwt() ->> 'email')
  );

-- A user can see (and therefore know whether they already have) only
-- their own subscriptions. The push-sending Edge Function reads this
-- table with the service_role key, which bypasses RLS entirely, so it
-- can still look up any recipient's subscriptions.
drop policy if exists "push_subscriptions_select_own" on public.push_subscriptions;
create policy "push_subscriptions_select_own" on public.push_subscriptions
  for select using (user_email = (auth.jwt() ->> 'email'));

-- A user can remove their own subscription (e.g. re-registering after
-- the browser rotates the endpoint, or explicitly turning notifications
-- off). A full admin may clean up any row.
drop policy if exists "push_subscriptions_delete_own_or_admin" on public.push_subscriptions;
create policy "push_subscriptions_delete_own_or_admin" on public.push_subscriptions
  for delete using (
    user_email = (auth.jwt() ->> 'email')
    or public.is_full_admin()
  );
