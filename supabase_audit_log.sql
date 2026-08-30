-- ============================================================
-- Nova — Admin action audit log
-- ============================================================
-- Adds a tamper-resistant, database-level audit trail for destructive/
-- sensitive admin actions: content deletions, role changes, the
-- maintenance-mode kill switch, and force-logout.
--
-- Why database-level triggers instead of logging from app.js: a trigger
-- fires on the actual write to Postgres itself, so it can't be skipped by
-- calling the API a different way, from a different client, or by a bug
-- in the frontend code — it's not something app.js could accidentally
-- forget to call.
--
-- The log itself is write-once from the app's perspective: RLS grants no
-- INSERT/UPDATE/DELETE policy to any client role at all, so the only way
-- a row is ever written is through the SECURITY DEFINER trigger function
-- below, which runs as the function owner and bypasses RLS by design.
-- Even a compromised full-admin account cannot edit or delete a past
-- entry through the API.
--
-- Run this once in the Supabase SQL Editor.
-- ============================================================

create table if not exists public.audit_log (
  id bigint generated always as identity primary key,
  actor_email text,
  action text not null,        -- 'INSERT' | 'UPDATE' | 'DELETE'
  target_table text not null,
  target_id text,
  details jsonb,
  created_at timestamptz not null default now()
);

create index if not exists audit_log_created_at_idx on public.audit_log (created_at desc);

alter table public.audit_log enable row level security;

drop policy if exists "audit_log_select_full_admin" on public.audit_log;
create policy "audit_log_select_full_admin" on public.audit_log
  for select using (public.is_full_admin());

-- Belt-and-suspenders: even if RLS were ever disabled by accident, these
-- grants alone would still block every client role from writing directly.
revoke insert, update, delete on public.audit_log from authenticated, anon;

create or replace function public.audit_log_generic()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  actor text;
  row_id text;
  payload jsonb;
begin
  -- A logging failure must never block the real operation it's watching —
  -- swallow anything that goes wrong here instead of aborting the caller's
  -- transaction (e.g. a legitimate script delete).
  begin
    actor := coalesce(auth.jwt() ->> 'email', 'system');
    if (tg_op = 'DELETE') then
      payload := to_jsonb(old);
    else
      payload := to_jsonb(new);
    end if;
    -- Different audited tables use different primary-key column names
    -- (id / key / user_id) — try each rather than assuming one.
    row_id := coalesce(payload ->> 'id', payload ->> 'key', payload ->> 'user_id');
    insert into public.audit_log (actor_email, action, target_table, target_id, details)
    values (actor, tg_op, tg_table_name, row_id, payload);
  exception when others then
    null;
  end;
  if (tg_op = 'DELETE') then
    return old;
  else
    return new;
  end if;
end;
$$;

-- Content tables admins manage — full history of who created/changed/removed what.
drop trigger if exists trg_audit_scripts on public.scripts;
create trigger trg_audit_scripts after insert or update or delete on public.scripts
  for each row execute function public.audit_log_generic();

drop trigger if exists trg_audit_categories on public.categories;
create trigger trg_audit_categories after insert or update or delete on public.categories
  for each row execute function public.audit_log_generic();

drop trigger if exists trg_audit_general_info on public.general_info;
create trigger trg_audit_general_info after insert or update or delete on public.general_info
  for each row execute function public.audit_log_generic();

drop trigger if exists trg_audit_critical_items on public.critical_items;
create trigger trg_audit_critical_items after insert or update or delete on public.critical_items
  for each row execute function public.audit_log_generic();

drop trigger if exists trg_audit_etiquette_items on public.etiquette_items;
create trigger trg_audit_etiquette_items after insert or update or delete on public.etiquette_items
  for each row execute function public.audit_log_generic();

drop trigger if exists trg_audit_updates on public.updates;
create trigger trg_audit_updates after insert or delete on public.updates
  for each row execute function public.audit_log_generic();

drop trigger if exists trg_audit_suggestions_delete on public.suggestions;
create trigger trg_audit_suggestions_delete after delete on public.suggestions
  for each row execute function public.audit_log_generic();

-- Employee-reported data admins can delete — accountability for removing someone else's report.
drop trigger if exists trg_audit_technical_issues_delete on public.technical_issues;
create trigger trg_audit_technical_issues_delete after delete on public.technical_issues
  for each row execute function public.audit_log_generic();

-- The three highest-stakes security actions in the app: pausing the whole
-- site, promoting/demoting someone's role, and force-logging someone out.
drop trigger if exists trg_audit_system_lock on public.system_lock;
create trigger trg_audit_system_lock after update on public.system_lock
  for each row execute function public.audit_log_generic();

drop trigger if exists trg_audit_profiles_role on public.profiles;
create trigger trg_audit_profiles_role after update of role on public.profiles
  for each row execute function public.audit_log_generic();

drop trigger if exists trg_audit_presence_force_logout on public.user_presence;
create trigger trg_audit_presence_force_logout after update of force_logout_at on public.user_presence
  for each row execute function public.audit_log_generic();

-- Quick sanity check after running this file — should show all triggers attached.
select event_object_table, trigger_name
from information_schema.triggers
where trigger_schema = 'public' and trigger_name like 'trg_audit_%'
order by event_object_table;
