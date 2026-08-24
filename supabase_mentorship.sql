-- =====================================================================
-- Nova (esclationsys) — Mentorship ("Buddy System") requests + chat
-- =====================================================================
-- WHY THIS FILE EXISTS
-- Adds two tables so a trainee can request a specific colleague as
-- their mentor by email, that colleague can accept or decline, and
-- once accepted the pair gets a private Q&A thread. There is no
-- general employee directory in this app (profiles/user_presence are
-- both locked to "own row or admin" by design — see
-- supabase_rls_policies.sql), so a trainee must know and type the
-- mentor's email directly; this file does not change that.
--
-- HOW TO APPLY
-- Run this once in the Supabase project's SQL Editor. Safe to re-run:
-- CREATE TABLE IF NOT EXISTS, and each policy is dropped before being
-- recreated. Assumes supabase_rls_policies.sql has already been
-- applied (reuses public.is_full_admin()).
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
