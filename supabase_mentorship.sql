-- =====================================================================
-- Nova (esclationsys) — Mentorship ("Buddy System") requests + chat
-- =====================================================================
-- WHY THIS FILE EXISTS
-- Adds two tables so a trainee can request a specific colleague as
-- their mentor, that colleague can accept or decline, and once
-- accepted the pair gets a private Q&A thread. There is no general
-- employee directory in this app otherwise (profiles/user_presence
-- are both locked to "own row or admin" by design — see
-- supabase_rls_policies.sql), so this file also adds a narrow
-- SECURITY DEFINER function that returns just the email addresses of
-- every account that can sign in (i.e. every row in auth.users), so
-- the mentor picker can be a dropdown instead of free-text.
--
-- SECURITY NOTE: list_directory_emails() intentionally exposes every
-- employee's email address to every other signed-in employee (email
-- only — no password, role, or other profile data). That is a real,
-- deliberate widening from "each user can only read their own info"
-- to "any employee can see the email directory." Skip that function
-- (and adjust the mentor-picker UI back to free-text) if that's not
-- something you want.
--
-- HOW TO APPLY
-- Run this once in the Supabase project's SQL Editor. Safe to re-run:
-- CREATE TABLE IF NOT EXISTS, CREATE OR REPLACE FUNCTION, and each
-- policy is dropped before being recreated. Assumes
-- supabase_rls_policies.sql has already been applied (reuses
-- public.is_full_admin()).
-- =====================================================================

create table if not exists public.mentor_requests (
  id bigint generated always as identity primary key,
  trainee_email text not null,
  mentor_email text not null,
  note text,
  status text not null default 'pending' check (status in ('pending', 'accepted', 'declined')),
  created_at timestamptz not null default now(),
  responded_at timestamptz,
  constraint mentor_requests_not_self check (trainee_email <> mentor_email)
);

create table if not exists public.mentor_messages (
  id bigint generated always as identity primary key,
  request_id bigint not null references public.mentor_requests(id) on delete cascade,
  sender_email text not null,
  text text not null,
  created_at timestamptz not null default now()
);

alter table public.mentor_requests enable row level security;
alter table public.mentor_messages enable row level security;

-- A trainee can only ever file a request as themselves.
drop policy if exists "mentor_requests_insert_own" on public.mentor_requests;
create policy "mentor_requests_insert_own" on public.mentor_requests
  for insert with check (
    auth.role() = 'authenticated'
    and trainee_email = (auth.jwt() ->> 'email')
  );

-- Either side of a request can see it (the trainee who sent it, or
-- the colleague who was asked to mentor).
drop policy if exists "mentor_requests_select_participant" on public.mentor_requests;
create policy "mentor_requests_select_participant" on public.mentor_requests
  for select using (
    trainee_email = (auth.jwt() ->> 'email')
    or mentor_email = (auth.jwt() ->> 'email')
  );

-- Only the invited mentor can accept/decline (flip status).
drop policy if exists "mentor_requests_update_mentor" on public.mentor_requests;
create policy "mentor_requests_update_mentor" on public.mentor_requests
  for update using (mentor_email = (auth.jwt() ->> 'email'))
  with check (mentor_email = (auth.jwt() ->> 'email'));

-- The trainee may cancel their own still-pending request; a full
-- admin may remove any request.
drop policy if exists "mentor_requests_delete_own_pending_or_admin" on public.mentor_requests;
create policy "mentor_requests_delete_own_pending_or_admin" on public.mentor_requests
  for delete using (
    public.is_full_admin()
    or (trainee_email = (auth.jwt() ->> 'email') and status = 'pending')
  );

-- Messages: only the two matched people (trainee/mentor of an
-- ACCEPTED request) can post into that thread...
drop policy if exists "mentor_messages_insert_own_thread" on public.mentor_messages;
create policy "mentor_messages_insert_own_thread" on public.mentor_messages
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

-- ...and only those same two people can read that thread back.
drop policy if exists "mentor_messages_select_own_thread" on public.mentor_messages;
create policy "mentor_messages_select_own_thread" on public.mentor_messages
  for select using (
    exists (
      select 1 from public.mentor_requests r
      where r.id = mentor_messages.request_id
        and (r.trainee_email = (auth.jwt() ->> 'email') or r.mentor_email = (auth.jwt() ->> 'email'))
    )
  );

drop policy if exists "mentor_messages_delete_full_admin" on public.mentor_messages;
create policy "mentor_messages_delete_full_admin" on public.mentor_messages
  for delete using (public.is_full_admin());


-- ---------------------------------------------------------------------
-- Mentor picker directory: every email address that can sign in.
-- SECURITY DEFINER so it can read auth.users (not otherwise exposed
-- to PostgREST) while returning nothing but the email column. See
-- the security note at the top of this file before applying.
-- ---------------------------------------------------------------------
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

-- ---------------------------------------------------------------------
-- Realtime: without this, a new request, an accept/decline, etc. only
-- ever shows up for the other side after a manual refresh — Supabase
-- only streams postgres_changes for tables explicitly added to this
-- publication. Realtime still goes through mentor_requests' own RLS
-- policies above (a client only receives rows it's allowed to select),
-- so this doesn't widen who can see what.
-- ---------------------------------------------------------------------
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'mentor_requests'
  ) then
    alter publication supabase_realtime add table public.mentor_requests;
  end if;
end $$;
