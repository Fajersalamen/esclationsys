-- =====================================================================
-- Nova (esclationsys) — Add the missing UPDATE policy on push_subscriptions
-- =====================================================================
-- app.js re-subscribes silently on every boot if permission was already
-- granted (syncPushSubscriptionIfGranted), saving via an upsert keyed
-- on the unique `endpoint` column. PostgREST's upsert becomes
-- `INSERT ... ON CONFLICT (endpoint) DO UPDATE ...` under the hood —
-- when that conflict path is taken (the same browser subscribing
-- again), Postgres RLS requires an UPDATE policy to allow it, not just
-- the INSERT policy. supabase_push_subscriptions.sql only defined
-- INSERT/SELECT/DELETE, so every re-subscribe after the first one was
-- silently rejected with a 403 — visible in the browser console as a
-- failed request with `on_conflict=endpoint` in the URL.
--
-- Safe to re-run.
-- =====================================================================

drop policy if exists "push_subscriptions_update_own" on public.push_subscriptions;
create policy "push_subscriptions_update_own" on public.push_subscriptions
  for update using (user_email = (auth.jwt() ->> 'email'))
  with check (user_email = (auth.jwt() ->> 'email'));
