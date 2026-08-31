-- ============================================================
-- Nova — Daily break schedule (replaces the daily Teams screenshot)
-- ============================================================
-- Two tables:
--   break_schedule       — one row per employee per day, 3 break times.
--   break_swap_requests  — a pending/accepted/declined request to swap
--                           one break slot with a colleague's.
--
-- Accepting a swap is done through respond_break_swap(), a SECURITY
-- DEFINER function that atomically swaps the two times and marks the
-- request handled — this can't be done safely as two separate client
-- UPDATE calls without risking a half-applied swap if one fails.
--
-- Run this once in the Supabase SQL Editor.
-- ============================================================

create table if not exists public.break_schedule (
  id bigint generated always as identity primary key,
  employee_email text not null,
  work_date date not null,
  break1_time time,
  break2_time time,
  break3_time time,
  updated_by text,
  updated_at timestamptz not null default now(),
  unique (employee_email, work_date)
);

create index if not exists break_schedule_work_date_idx on public.break_schedule (work_date);

alter table public.break_schedule enable row level security;

drop policy if exists "break_schedule_select_authenticated" on public.break_schedule;
create policy "break_schedule_select_authenticated" on public.break_schedule
  for select using (auth.role() = 'authenticated');

drop policy if exists "break_schedule_write_admin_or_lead" on public.break_schedule;
create policy "break_schedule_write_admin_or_lead" on public.break_schedule
  for all using (public.is_admin_or_lead()) with check (public.is_admin_or_lead());

create table if not exists public.break_swap_requests (
  id bigint generated always as identity primary key,
  work_date date not null,
  requester_email text not null,
  requester_break_slot smallint not null check (requester_break_slot between 1 and 3),
  target_email text not null,
  target_break_slot smallint not null check (target_break_slot between 1 and 3),
  status text not null default 'pending' check (status in ('pending', 'accepted', 'declined')),
  created_at timestamptz not null default now(),
  responded_at timestamptz,
  check (requester_email <> target_email)
);

create index if not exists break_swap_requests_work_date_idx on public.break_swap_requests (work_date);

alter table public.break_swap_requests enable row level security;

-- Everyone involved (either side) can see a request; admins/leads see all of them too.
drop policy if exists "break_swap_select_involved" on public.break_swap_requests;
create policy "break_swap_select_involved" on public.break_swap_requests
  for select using (
    requester_email = (auth.jwt() ->> 'email')
    or target_email = (auth.jwt() ->> 'email')
    or public.is_admin_or_lead()
  );

-- Anyone can send a request, but only as themselves.
drop policy if exists "break_swap_insert_self" on public.break_swap_requests;
create policy "break_swap_insert_self" on public.break_swap_requests
  for insert with check (
    auth.role() = 'authenticated' and requester_email = (auth.jwt() ->> 'email')
  );

-- No direct UPDATE/DELETE policy on purpose — accepting/declining goes
-- through respond_break_swap() below, which bypasses RLS as its owner.
-- This keeps a swap from ever being half-applied (times updated but the
-- request left "pending", or vice versa) since it's all one transaction.

create or replace function public.respond_break_swap(request_id bigint, accept boolean)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  req record;
  requester_time time;
  target_time time;
  caller_email text;
begin
  caller_email := auth.jwt() ->> 'email';

  select * into req from public.break_swap_requests where id = request_id and status = 'pending';
  if not found then
    raise exception 'Request not found or already handled';
  end if;
  if caller_email is distinct from req.target_email then
    raise exception 'Only the target employee can respond to this request';
  end if;

  if accept then
    select case req.requester_break_slot when 1 then break1_time when 2 then break2_time when 3 then break3_time end
      into requester_time
      from public.break_schedule where employee_email = req.requester_email and work_date = req.work_date;

    select case req.target_break_slot when 1 then break1_time when 2 then break2_time when 3 then break3_time end
      into target_time
      from public.break_schedule where employee_email = req.target_email and work_date = req.work_date;

    update public.break_schedule set
      break1_time = case when req.requester_break_slot = 1 then target_time else break1_time end,
      break2_time = case when req.requester_break_slot = 2 then target_time else break2_time end,
      break3_time = case when req.requester_break_slot = 3 then target_time else break3_time end,
      updated_at = now()
    where employee_email = req.requester_email and work_date = req.work_date;

    update public.break_schedule set
      break1_time = case when req.target_break_slot = 1 then requester_time else break1_time end,
      break2_time = case when req.target_break_slot = 2 then requester_time else break2_time end,
      break3_time = case when req.target_break_slot = 3 then requester_time else break3_time end,
      updated_at = now()
    where employee_email = req.target_email and work_date = req.work_date;

    update public.break_swap_requests set status = 'accepted', responded_at = now() where id = request_id;
  else
    update public.break_swap_requests set status = 'declined', responded_at = now() where id = request_id;
  end if;
end;
$$;

-- Track admin edits to the break table in the audit log. Requires
-- supabase_audit_log.sql to have been run first (for audit_log_generic()
-- to exist) — already the case in this project.
drop trigger if exists trg_audit_break_schedule on public.break_schedule;
create trigger trg_audit_break_schedule after insert or update or delete on public.break_schedule
  for each row execute function public.audit_log_generic();

-- Admin/lead "seat swap": reassigns which employee sits in two existing
-- schedule rows without touching either row's break times. The two rows
-- keep their own break1/2/3_time values exactly as they were — only the
-- employee_email (and updated_by/updated_at) moves between them.
--
-- Done as a 3-step update through a placeholder value rather than a single
-- CASE-based UPDATE, since employee_email is part of a unique constraint
-- with work_date and a same-statement two-row swap of a unique column can
-- collide with itself mid-statement. Row locks (for update) keep two
-- concurrent swaps from interleaving.
create or replace function public.swap_break_seats(row_id_a bigint, row_id_b bigint)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  email_a text;
  email_b text;
  date_a date;
  date_b date;
  caller_email text;
begin
  if not public.is_admin_or_lead() then
    raise exception 'Only an admin or team lead can reassign break seats';
  end if;

  caller_email := auth.jwt() ->> 'email';

  select employee_email, work_date into email_a, date_a from public.break_schedule where id = row_id_a for update;
  select employee_email, work_date into email_b, date_b from public.break_schedule where id = row_id_b for update;

  if email_a is null or email_b is null then
    raise exception 'One of these seats no longer exists';
  end if;
  if date_a is distinct from date_b then
    raise exception 'Seats must be on the same day';
  end if;

  update public.break_schedule set employee_email = '__swap_tmp__' || row_id_a::text, updated_by = caller_email, updated_at = now() where id = row_id_a;
  update public.break_schedule set employee_email = email_a, updated_by = caller_email, updated_at = now() where id = row_id_b;
  update public.break_schedule set employee_email = email_b, updated_by = caller_email, updated_at = now() where id = row_id_a;
end;
$$;

grant execute on function public.swap_break_seats(bigint, bigint) to authenticated;
