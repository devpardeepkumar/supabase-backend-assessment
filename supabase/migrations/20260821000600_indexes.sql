-- Hot-path indexes for the assessment scale. Partial/composite where justified.

CREATE INDEX IF NOT EXISTS organisation_memberships_user_id_idx
  ON public.organisation_memberships (user_id)
  WHERE status = 'active';

CREATE INDEX IF NOT EXISTS organisation_memberships_org_role_idx
  ON public.organisation_memberships (organisation_id, role)
  WHERE status = 'active';

CREATE INDEX IF NOT EXISTS projects_org_activity_idx
  ON public.projects (organisation_id, last_activity_at DESC)
  WHERE archived_at IS NULL;

CREATE INDEX IF NOT EXISTS project_memberships_user_id_idx
  ON public.project_memberships (user_id);

CREATE INDEX IF NOT EXISTS project_memberships_project_id_idx
  ON public.project_memberships (project_id);

CREATE INDEX IF NOT EXISTS tasks_project_status_position_idx
  ON public.tasks (project_id, status, position);

CREATE INDEX IF NOT EXISTS comments_project_created_idx
  ON public.comments (project_id, created_at DESC);

CREATE INDEX IF NOT EXISTS invitations_token_hash_pending_idx
  ON public.invitations (token_hash)
  WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS audit_events_org_created_idx
  ON public.audit_events (organisation_id, created_at DESC);

CREATE INDEX IF NOT EXISTS webhook_events_provider_event_idx
  ON public.webhook_events (provider, event_id);

CREATE INDEX IF NOT EXISTS project_files_project_idx
  ON public.project_files (project_id);

-- Deliberately omitted: comments(author_id). Writes are frequent at 200M rows;
-- author lookup is not a documented hot path. See PERFORMANCE.md.
