-- =====================================================================
-- Nova (esclationsys) — Image attachments (Updates composer + Mentor chat)
-- =====================================================================
-- WHY THIS FILE EXISTS
-- Adds image support to two places:
--   1. The admin "post a new update" composer — an optional attached photo.
--   2. The mentorship 1:1 chat — pasting a screenshot (or picking a file)
--      sends it as an image message.
-- Both upload into one shared public Storage bucket ("attachments"),
-- under a per-feature folder prefix (updates/... or mentor-chat/...).
--
-- HOW TO APPLY
-- Run this once in the Supabase project's SQL Editor. Safe to re-run:
-- the bucket insert is ON CONFLICT DO NOTHING, each storage policy is
-- dropped before being recreated, and both ALTER TABLE ADD COLUMN
-- statements use IF NOT EXISTS. Assumes supabase_mentorship.sql has
-- already been applied (this extends public.mentor_messages).
-- =====================================================================

-- ---------------------------------------------------------------------
-- Storage bucket: public so images load via a plain public URL (no
-- signed-URL round trip needed just to show a photo in a chat bubble or
-- an update card). A 8 MB cap is enforced here too, as a backstop behind
-- the client-side downscale the app does before every upload.
-- ---------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('attachments', 'attachments', true, 8388608, array['image/png', 'image/jpeg', 'image/webp', 'image/gif'])
on conflict (id) do update set
  public = true,
  file_size_limit = 8388608,
  allowed_mime_types = array['image/png', 'image/jpeg', 'image/webp', 'image/gif'];

-- Any signed-in employee can upload into this bucket (both features are
-- already gated to signed-in users at the page level); nobody can
-- overwrite or delete another person's file, and reads are public
-- (the bucket-level `public = true` above already serves objects over
-- their public URL regardless of RLS, but SELECT is still granted here
-- so authenticated in-app calls like getPublicUrl-adjacent listing work
-- the same way for everyone).
drop policy if exists "attachments_insert_authenticated" on storage.objects;
create policy "attachments_insert_authenticated" on storage.objects
  for insert with check (
    bucket_id = 'attachments' and auth.role() = 'authenticated'
  );

drop policy if exists "attachments_select_public" on storage.objects;
create policy "attachments_select_public" on storage.objects
  for select using (bucket_id = 'attachments');

drop policy if exists "attachments_delete_own_or_admin" on storage.objects;
create policy "attachments_delete_own_or_admin" on storage.objects
  for delete using (
    bucket_id = 'attachments'
    and (owner = auth.uid() or public.is_full_admin())
  );

-- ---------------------------------------------------------------------
-- updates: an optional photo alongside the announcement text.
-- ---------------------------------------------------------------------
alter table public.updates add column if not exists image_url text;

-- ---------------------------------------------------------------------
-- mentor_messages: an optional photo per chat message. `text` stays
-- NOT NULL at the column level in the existing table, so the app sends
-- '' (empty string) for an image-only message rather than null — the
-- check constraint below is what actually enforces "at least one of
-- text or image_url is present" so an empty, contentless row can never
-- be inserted.
-- ---------------------------------------------------------------------
alter table public.mentor_messages add column if not exists image_url text;

alter table public.mentor_messages drop constraint if exists mentor_messages_has_content;
alter table public.mentor_messages add constraint mentor_messages_has_content
  check (coalesce(text, '') <> '' or image_url is not null);
