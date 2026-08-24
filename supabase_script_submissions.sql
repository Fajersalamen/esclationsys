-- =====================================================================
-- Nova (esclationsys) — "Contribute a Fix" crowd-sourced script library
-- =====================================================================
-- WHY THIS FILE EXISTS
-- Adds a new table, script_submissions, so any employee can submit a
-- script they wrote themselves (a fix for a situation not already
-- covered in the Script Library) for admin/team_leader review. On
-- approval the app copies the submission into the real `scripts`
-- table via the existing script-editor flow; nothing here writes to
-- `scripts` directly.
--
-- HOW TO APPLY
-- Run this once in the Supabase project's SQL Editor (Dashboard → SQL
-- Editor → New query → paste → Run). Safe to re-run: CREATE TABLE IF
-- NOT EXISTS, and each policy is dropped before being recreated.
--
-- This assumes supabase_rls_policies.sql has already been applied
-- (it defines public.is_admin_or_lead() / public.is_full_admin(),
-- which the policies below reuse).
-- =====================================================================

create table if not exists public.script_submissions (
  id bigint generated always as identity primary key,
  cat text not null,
  title text not null,
  title_ar text,
  text text not null,
  text_ar text,
  submitted_by text not null,          -- employee email, matches auth.jwt() ->> 'email'
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  reviewed_by text,
  created_at timestamptz not null default now()
);

alter table public.script_submissions enable row level security;

-- Any signed-in employee can submit their own contribution.
drop policy if exists "script_submissions_insert_own_email" on public.script_submissions;
create policy "script_submissions_insert_own_email" on public.script_submissions
  for insert with check (
    auth.role() = 'authenticated'
    and submitted_by = (auth.jwt() ->> 'email')
  );

-- An employee can see their own submissions (to check the status);
-- admin/team_leader can see everyone's, for review.
drop policy if exists "script_submissions_select_own_or_admin" on public.script_submissions;
create policy "script_submissions_select_own_or_admin" on public.script_submissions
  for select using (
    submitted_by = (auth.jwt() ->> 'email')
    or public.is_admin_or_lead()
  );

-- Only admin/team_leader may approve/reject (update status).
drop policy if exists "script_submissions_update_admin" on public.script_submissions;
create policy "script_submissions_update_admin" on public.script_submissions
  for update using (public.is_admin_or_lead()) with check (public.is_admin_or_lead());

-- Only a full admin may delete a submission outright.
drop policy if exists "script_submissions_delete_full_admin" on public.script_submissions;
create policy "script_submissions_delete_full_admin" on public.script_submissions
  for delete using (public.is_full_admin());
