-- RLS is the client security boundary. USING + WITH CHECK prevent tenant moves.
-- Membership policies never query the same table under RLS; they use app_hidden helpers.

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organisations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organisation_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.project_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.project_files ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.profiles FORCE ROW LEVEL SECURITY;
ALTER TABLE public.organisations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.organisation_memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE public.projects FORCE ROW LEVEL SECURITY;
ALTER TABLE public.project_memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tasks FORCE ROW LEVEL SECURITY;
ALTER TABLE public.comments FORCE ROW LEVEL SECURITY;
ALTER TABLE public.invitations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.audit_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.project_files FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own profile." ON public.profiles;
DROP POLICY IF EXISTS "Users can update their own profile." ON public.profiles;
DROP POLICY IF EXISTS "Organisation owners can manage their organisation." ON public.organisations;

-- Profiles: self, or anyone who shares an organisation (not a global directory).
CREATE POLICY profiles_select ON public.profiles
  FOR SELECT TO authenticated
  USING (
    id = auth.uid()
    OR EXISTS (
      SELECT 1
      FROM public.organisation_memberships mine
      JOIN public.organisation_memberships theirs
        ON theirs.organisation_id = mine.organisation_id
      WHERE mine.user_id = auth.uid()
        AND mine.status = 'active'
        AND mine.role IN ('owner', 'admin', 'member')
        AND theirs.user_id = profiles.id
        AND theirs.status = 'active'
    )
  );

CREATE POLICY profiles_update_self ON public.profiles
  FOR UPDATE TO authenticated
  USING (id = auth.uid())
  WITH CHECK (id = auth.uid());

-- Organisations
CREATE POLICY organisations_select ON public.organisations
  FOR SELECT TO authenticated
  USING (app_hidden.org_role(id) IS NOT NULL);

CREATE POLICY organisations_insert ON public.organisations
  FOR INSERT TO authenticated
  WITH CHECK (true);

CREATE POLICY organisations_update ON public.organisations
  FOR UPDATE TO authenticated
  USING (app_hidden.org_role(id) IN ('owner', 'admin'))
  WITH CHECK (app_hidden.org_role(id) IN ('owner', 'admin'));

CREATE POLICY organisations_delete ON public.organisations
  FOR DELETE TO authenticated
  USING (app_hidden.org_role(id) = 'owner');

-- After org insert, caller becomes owner. SECURITY DEFINER so it can write membership
-- before the caller's org_role exists.
CREATE OR REPLACE FUNCTION app_hidden.claim_org_owner()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF auth.uid() IS NULL THEN
    RETURN NEW;
  END IF;
  INSERT INTO public.organisation_memberships (organisation_id, user_id, role, status)
  VALUES (NEW.id, auth.uid(), 'owner', 'active')
  ON CONFLICT (organisation_id, user_id) DO NOTHING;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS organisations_claim_owner ON public.organisations;
CREATE TRIGGER organisations_claim_owner
  AFTER INSERT ON public.organisations
  FOR EACH ROW
  EXECUTE FUNCTION app_hidden.claim_org_owner();

REVOKE ALL ON FUNCTION app_hidden.claim_org_owner() FROM PUBLIC;

-- Organisation memberships: no self-join via RLS.
-- SELECT: owner/admin see all; member sees all members (not used as guest directory);
-- guest sees only their own row.
CREATE POLICY org_memberships_select ON public.organisation_memberships
  FOR SELECT TO authenticated
  USING (
    user_id = auth.uid()
    OR app_hidden.org_role(organisation_id) IN ('owner', 'admin', 'member')
  );

CREATE POLICY org_memberships_insert ON public.organisation_memberships
  FOR INSERT TO authenticated
  WITH CHECK (
    app_hidden.org_role(organisation_id) IN ('owner', 'admin')
    AND role <> 'owner'
    AND NOT (
      app_hidden.org_role(organisation_id) = 'admin'
      AND role IN ('owner', 'admin')
    )
  );

-- Ordinary membership UPDATE cannot create/replace an owner or demote the owner.
CREATE POLICY org_memberships_update ON public.organisation_memberships
  FOR UPDATE TO authenticated
  USING (
    app_hidden.org_role(organisation_id) IN ('owner', 'admin')
    AND role <> 'owner'
  )
  WITH CHECK (
    app_hidden.org_role(organisation_id) IN ('owner', 'admin')
    AND role <> 'owner'
    AND NOT (
      app_hidden.org_role(organisation_id) = 'admin'
      AND role = 'admin'
    )
  );

CREATE POLICY org_memberships_delete ON public.organisation_memberships
  FOR DELETE TO authenticated
  USING (
    app_hidden.org_role(organisation_id) IN ('owner', 'admin')
    AND role <> 'owner'
    AND user_id <> auth.uid()
  );

-- Projects
CREATE POLICY projects_select ON public.projects
  FOR SELECT TO authenticated
  USING (app_hidden.can_view_project(id));

CREATE POLICY projects_insert ON public.projects
  FOR INSERT TO authenticated
  WITH CHECK (app_hidden.org_role(organisation_id) IN ('owner', 'admin'));

CREATE POLICY projects_update ON public.projects
  FOR UPDATE TO authenticated
  USING (app_hidden.can_edit_project(id))
  WITH CHECK (
    app_hidden.can_edit_project(id)
    AND organisation_id = app_hidden.project_org(id)
  );

CREATE POLICY projects_delete ON public.projects
  FOR DELETE TO authenticated
  USING (app_hidden.org_role(organisation_id) IN ('owner', 'admin'));

-- Project memberships
CREATE POLICY project_memberships_select ON public.project_memberships
  FOR SELECT TO authenticated
  USING (app_hidden.can_view_project(project_id));

CREATE POLICY project_memberships_insert ON public.project_memberships
  FOR INSERT TO authenticated
  WITH CHECK (app_hidden.can_manage_project_members(project_id));

CREATE POLICY project_memberships_update ON public.project_memberships
  FOR UPDATE TO authenticated
  USING (app_hidden.can_manage_project_members(project_id))
  WITH CHECK (app_hidden.can_manage_project_members(project_id));

CREATE POLICY project_memberships_delete ON public.project_memberships
  FOR DELETE TO authenticated
  USING (app_hidden.can_manage_project_members(project_id));

-- Tasks
CREATE POLICY tasks_select ON public.tasks
  FOR SELECT TO authenticated
  USING (app_hidden.can_view_project(project_id));

CREATE POLICY tasks_insert ON public.tasks
  FOR INSERT TO authenticated
  WITH CHECK (
    app_hidden.can_write_project_content(project_id)
    AND created_by = auth.uid()
  );

CREATE POLICY tasks_update ON public.tasks
  FOR UPDATE TO authenticated
  USING (app_hidden.can_update_task(id))
  WITH CHECK (
    app_hidden.can_update_task(id)
    AND project_id = (SELECT t.project_id FROM public.tasks t WHERE t.id = tasks.id)
  );

CREATE POLICY tasks_delete ON public.tasks
  FOR DELETE TO authenticated
  USING (
    app_hidden.org_role(app_hidden.project_org(project_id)) IN ('owner', 'admin')
    OR app_hidden.project_role(project_id) = 'manager'
  );

-- Comments
CREATE POLICY comments_select ON public.comments
  FOR SELECT TO authenticated
  USING (app_hidden.can_view_project(project_id));

CREATE POLICY comments_insert ON public.comments
  FOR INSERT TO authenticated
  WITH CHECK (
    app_hidden.can_write_project_content(project_id)
    AND author_id = auth.uid()
  );

CREATE POLICY comments_update ON public.comments
  FOR UPDATE TO authenticated
  USING (
    author_id = auth.uid()
    OR app_hidden.project_role(project_id) = 'manager'
    OR app_hidden.org_role(app_hidden.project_org(project_id)) IN ('owner', 'admin')
  )
  WITH CHECK (
    project_id = (SELECT c.project_id FROM public.comments c WHERE c.id = comments.id)
    AND author_id = (SELECT c.author_id FROM public.comments c WHERE c.id = comments.id)
  );

CREATE POLICY comments_delete ON public.comments
  FOR DELETE TO authenticated
  USING (
    author_id = auth.uid()
    OR app_hidden.project_role(project_id) = 'manager'
    OR app_hidden.org_role(app_hidden.project_org(project_id)) IN ('owner', 'admin')
  );

-- Invitations: visible to owner/admin of the org only. Token hash never selected by guests.
CREATE POLICY invitations_select ON public.invitations
  FOR SELECT TO authenticated
  USING (app_hidden.org_role(organisation_id) IN ('owner', 'admin'));

CREATE POLICY invitations_insert ON public.invitations
  FOR INSERT TO authenticated
  WITH CHECK (
    app_hidden.org_role(organisation_id) IN ('owner', 'admin')
    AND invited_by = auth.uid()
    AND intended_role <> 'owner'
  );

CREATE POLICY invitations_update ON public.invitations
  FOR UPDATE TO authenticated
  USING (app_hidden.org_role(organisation_id) IN ('owner', 'admin'))
  WITH CHECK (app_hidden.org_role(organisation_id) IN ('owner', 'admin'));

-- Audit: append-only for clients. Inserts happen via SECURITY DEFINER functions.
CREATE POLICY audit_events_select ON public.audit_events
  FOR SELECT TO authenticated
  USING (
    organisation_id IS NOT NULL
    AND app_hidden.org_role(organisation_id) IN ('owner', 'admin')
  );

-- No INSERT/UPDATE/DELETE policies for authenticated on audit_events or webhook_events.

CREATE POLICY project_files_select ON public.project_files
  FOR SELECT TO authenticated
  USING (app_hidden.can_view_project(project_id));

CREATE POLICY project_files_insert ON public.project_files
  FOR INSERT TO authenticated
  WITH CHECK (
    app_hidden.can_write_project_content(project_id)
    AND uploaded_by = auth.uid()
    AND organisation_id = app_hidden.project_org(project_id)
  );

CREATE POLICY project_files_delete ON public.project_files
  FOR DELETE TO authenticated
  USING (
    uploaded_by = auth.uid()
    OR app_hidden.project_role(project_id) = 'manager'
    OR app_hidden.org_role(organisation_id) IN ('owner', 'admin')
  );

-- Privileges: least privilege. Anon gets nothing on tenant tables.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon;

GRANT USAGE ON SCHEMA public TO anon, authenticated;

GRANT SELECT, UPDATE (full_name, avatar_url, updated_at) ON public.profiles TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.organisations TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.organisation_memberships TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.projects TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.project_memberships TO authenticated;
GRANT SELECT, INSERT, DELETE ON public.tasks TO authenticated;
GRANT UPDATE (
  title, description, status, position, assignee_id, version, updated_at
) ON public.tasks TO authenticated;
GRANT SELECT, INSERT, DELETE ON public.comments TO authenticated;
GRANT UPDATE (body, updated_at) ON public.comments TO authenticated;
GRANT SELECT, INSERT, UPDATE ON public.invitations TO authenticated;
GRANT SELECT ON public.audit_events TO authenticated;
GRANT SELECT, INSERT, DELETE ON public.project_files TO authenticated;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO authenticated;
