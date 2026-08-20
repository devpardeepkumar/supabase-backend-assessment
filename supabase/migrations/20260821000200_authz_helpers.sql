-- Authorization helpers live in app_hidden so membership checks never recurse
-- through RLS. They are SECURITY DEFINER, locked search_path, and not granted
-- to clients. Public wrappers are the only callable surface.

CREATE OR REPLACE FUNCTION app_hidden.jwt_email()
RETURNS text
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $$
  SELECT lower(coalesce(auth.jwt()->>'email', ''));
$$;

CREATE OR REPLACE FUNCTION app_hidden.org_role(_org_id uuid)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT m.role
  FROM public.organisation_memberships m
  WHERE m.organisation_id = _org_id
    AND m.user_id = auth.uid()
    AND m.status = 'active'
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION app_hidden.project_role(_project_id uuid)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT pm.role
  FROM public.project_memberships pm
  WHERE pm.project_id = _project_id
    AND pm.user_id = auth.uid()
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION app_hidden.project_org(_project_id uuid)
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT p.organisation_id
  FROM public.projects p
  WHERE p.id = _project_id;
$$;

-- Baseline: owner/admin of the org OR explicit project membership.
-- Confidential mode is applied in a later migration by changing ONLY this function.
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
        app_hidden.org_role(p.organisation_id) IN ('owner', 'admin')
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
  SELECT
    app_hidden.org_role(app_hidden.project_org(_project_id)) IN ('owner', 'admin')
    OR app_hidden.project_role(_project_id) = 'manager';
$$;

CREATE OR REPLACE FUNCTION app_hidden.can_manage_project_members(_project_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT app_hidden.can_edit_project(_project_id);
$$;

CREATE OR REPLACE FUNCTION app_hidden.can_write_project_content(_project_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT
    app_hidden.org_role(app_hidden.project_org(_project_id)) IN ('owner', 'admin')
    OR app_hidden.project_role(_project_id) IN ('manager', 'contributor');
$$;

CREATE OR REPLACE FUNCTION app_hidden.can_update_task(_task_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.tasks t
    WHERE t.id = _task_id
      AND (
        app_hidden.org_role(app_hidden.project_org(t.project_id)) IN ('owner', 'admin')
        OR app_hidden.project_role(t.project_id) = 'manager'
        OR (
          app_hidden.project_role(t.project_id) = 'contributor'
          AND (t.created_by = auth.uid() OR t.assignee_id = auth.uid())
        )
      )
  );
$$;

CREATE OR REPLACE FUNCTION public.can_view_project(_project_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT COALESCE(app_hidden.can_view_project(_project_id), false);
$$;

REVOKE ALL ON FUNCTION public.can_view_project(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.can_view_project(uuid) TO authenticated;

REVOKE ALL ON FUNCTION app_hidden.org_role(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_hidden.project_role(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_hidden.project_org(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_hidden.can_view_project(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_hidden.can_edit_project(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_hidden.can_manage_project_members(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_hidden.can_write_project_content(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_hidden.can_update_task(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_hidden.jwt_email() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_hidden.enforce_project_membership() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_hidden.prevent_project_org_move() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_hidden.touch_updated_at() FROM PUBLIC;

-- RLS policies run as the invoking role, so authenticated must be able to
-- execute the read-only helpers. Mutating definer functions stay ungranted.
GRANT USAGE ON SCHEMA app_hidden TO authenticated;
GRANT EXECUTE ON FUNCTION app_hidden.org_role(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION app_hidden.project_role(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION app_hidden.project_org(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION app_hidden.can_view_project(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION app_hidden.can_edit_project(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION app_hidden.can_manage_project_members(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION app_hidden.can_write_project_content(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION app_hidden.can_update_task(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION app_hidden.jwt_email() TO authenticated;
