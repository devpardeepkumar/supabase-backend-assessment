-- Change request: confidential projects.
-- Organisation admins lose automatic access unless explicitly in project_memberships.
-- Owner still has access. Normal projects keep owner/admin automatic access.
-- Only the central helper changes; table RLS, Storage, and Realtime call it.

ALTER TABLE public.projects
  ADD COLUMN IF NOT EXISTS access_mode text NOT NULL DEFAULT 'normal';

ALTER TABLE public.projects
  DROP CONSTRAINT IF EXISTS projects_access_mode_check;

ALTER TABLE public.projects
  ADD CONSTRAINT projects_access_mode_check
  CHECK (access_mode IN ('normal', 'confidential'));

CREATE OR REPLACE FUNCTION app_hidden.can_view_project(_project_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.projects p
    WHERE p.id = _project_id
      AND (
        app_hidden.org_role(p.organisation_id) = 'owner'
        OR (
          p.access_mode = 'normal'
          AND app_hidden.org_role(p.organisation_id) = 'admin'
        )
        OR EXISTS (
          SELECT 1
          FROM public.project_memberships pm
          WHERE pm.project_id = p.id
            AND pm.user_id = auth.uid()
        )
      )
  );
$$;

CREATE OR REPLACE FUNCTION app_hidden.can_edit_project(_project_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.projects p
    WHERE p.id = _project_id
      AND (
        app_hidden.org_role(p.organisation_id) = 'owner'
        OR (
          p.access_mode = 'normal'
          AND app_hidden.org_role(p.organisation_id) = 'admin'
        )
        OR app_hidden.project_role(_project_id) = 'manager'
      )
  );
$$;

CREATE OR REPLACE FUNCTION app_hidden.can_write_project_content(_project_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.projects p
    WHERE p.id = _project_id
      AND (
        app_hidden.org_role(p.organisation_id) = 'owner'
        OR (
          p.access_mode = 'normal'
          AND app_hidden.org_role(p.organisation_id) = 'admin'
        )
        OR app_hidden.project_role(_project_id) IN ('manager', 'contributor')
      )
  );
$$;
