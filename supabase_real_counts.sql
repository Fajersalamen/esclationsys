-- Real row counts (bypasses RLS — this is the true content of every table)
select 'categories' as table_name, count(*) as real_row_count from public.categories
union all select 'scripts', count(*) from public.scripts
union all select 'general_info', count(*) from public.general_info
union all select 'critical_items', count(*) from public.critical_items
union all select 'etiquette_items', count(*) from public.etiquette_items
union all select 'updates', count(*) from public.updates
union all select 'suggestions', count(*) from public.suggestions
union all select 'technical_issues', count(*) from public.technical_issues
union all select 'training_problems', count(*) from public.training_problems
union all select 'training_nodes', count(*) from public.training_nodes
union all select 'training_options', count(*) from public.training_options
order by table_name;
