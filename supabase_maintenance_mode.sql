-- =====================================================================
-- Nova (esclationsys) — Temporary shutdown / maintenance mode
-- =====================================================================
-- WHY THIS FILE EXISTS
-- A single-row switch a full admin can flip on to freeze the app for
-- every OTHER signed-in employee, instantly propagating (within one
-- presence heartbeat, ~20s) to every open tab without anyone needing
-- to refresh — same mechanism as the "deleted user gets signed out
-- automatically" fix: the client already polls the server every 20s,
-- this just adds one more thing it checks there.
--
-- SCOPE / HONEST LIMITATION
-- This is an operational pause, not a hard security boundary: it
-- blocks the normal UI for everyone but full admins, but does not by
-- itself add a database-level check to every other table's RLS
-- policies. Someone who already has a valid session and calls the
-- Supabase REST API directly (bypassing the UI) would not be stopped
-- by this alone. That's an intentional scope choice to keep this
-- simple and safe to layer on top of the existing RLS setup — ask if
-- you also want every table's policies to check this flag.
--
-- HOW TO APPLY
-- Run this once in the Supabase project's SQL Editor. Safe to re-run.
-- =====================================================================

create table if not exists public.system_lock (
  id smallint primary key default 1,
  locked boolean not null default false,
  message text,
  message_ar text,
  updated_by text,
  updated_at timestamptz not null default now(),
  constraint system_lock_singleton check (id = 1)
);

insert into public.system_lock (id, locked)
values (1, false)
on conflict (id) do nothing;

alter table public.system_lock enable row level security;

-- Every signed-in employee needs to read this (that's the whole point —
-- their client polls it to know whether to show the blocking overlay).
drop policy if exists "system_lock_select_authenticated" on public.system_lock;
create policy "system_lock_select_authenticated" on public.system_lock
  for select using (auth.role() = 'authenticated');

-- Only a full admin (not a limited team_leader) can flip the switch.
drop policy if exists "system_lock_update_full_admin" on public.system_lock;
create policy "system_lock_update_full_admin" on public.system_lock
  for update using (public.is_full_admin()) with check (public.is_full_admin());

-- No insert/delete policy on purpose — it's a fixed single row seeded
-- above; nobody, including admins, needs to insert or delete it.
