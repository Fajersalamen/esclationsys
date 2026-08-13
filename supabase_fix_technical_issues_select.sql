-- =====================================================================
-- Immediate fix: restore read access to technical_issues for signed-in
-- employees. Safe to run any number of times.
-- =====================================================================
alter table public.technical_issues enable row level security;

drop policy if exists "technical_issues_select_authenticated" on public.technical_issues;
create policy "technical_issues_select_authenticated" on public.technical_issues
  for select using (auth.role() = 'authenticated');

-- Confirms the policy now exists — should return exactly one row.
select policyname, cmd, qual
from pg_policies
where schemaname = 'public' and tablename = 'technical_issues' and cmd = 'SELECT';
